# Contribution Log

# Contribution [#2821]: Add authorization to provider settings save (fix IDOR)

**Contribution Number:** 2  
**Student:** Mahmuda Akter  
**Issue:** https://github.com/carlos-emr/carlos/issues/2821
**Fork Link:** (https://github.com/makter20/carlos)
**Status:** Phase I

## Why I Chose This Issue

I am always passionate about the healthcare field, and I care a lot about how patient and provider data is protected. This issue is a security vulnerability (an IDOR) that lets any logged-in user change another provider's settings, so it sits right at the intersection of healthcare and security that I want to grow in.

## Understanding the Issue

### Problem Description

The REST endpoint that saves provider settings takes the target provider number straight from the URL path (`POST /ws/rs/providerService/settings/{providerNo}/save`) and writes those settings for that provider. The only thing protecting it is that the caller must be logged in — there is **no check that the caller actually owns `{providerNo}` or is an administrator**. This is an Insecure Direct Object Reference (IDOR): any authenticated session can overwrite the settings of any provider in the system just by changing the number in the URL. A secondary problem is that the full settings object is written to the logs at `WARN` level on every save, which exposes provider configuration (fax number, Rx address, default billing codes) in application logs.

### Expected Behavior

1. A provider may save **only their own** settings.
2. Saving **another** provider's settings requires an administrator privilege, checked through `SecurityInfoManager.hasPrivilege(...)` on the `_admin` security object.
3. The caller's identity is taken from the **session**, not from the request URL.
4. Sensitive settings values are not written to the logs.

### Current Behavior

- Only a valid login session is required. The endpoint is served under `/ws/rs` behind `AuthenticationInInterceptor`, which confirms the user is logged in and nothing more.
- There is no `hasPrivilege` / ownership check. The `providerNo` from the URL path is trusted and passed straight into the manager.
- `ProviderService.saveProviderSettings` logs the entire `ProviderSettings` object at `WARN` on every call.
- `/ws/*` is CSRF-unprotected (`Owasp.CsrfGuard.unprotected.Soap`), so the write is also reachable as a cross-site request while a provider is logged in.

### Affected Components

- **`src/main/java/io/github/carlos_emr/carlos/webserv/rest/ProviderService.java`** — `saveProviderSettings(ProviderSettings, String providerNo)` (around line 412), the REST entrypoint that is missing the authorization check and that logs the settings object.
- **`src/main/java/io/github/carlos_emr/carlos/managers/ProviderManager2.java`** — `updateProviderSettings(LoggedInInfo, String providerNo, ProviderSettings)` (around line 475), which writes preferences and properties keyed on the caller-supplied `providerNo` and never uses `loggedInInfo` for authorization.
- The unit tests for `ProviderService`, which will need new cases for self-edit, cross-provider (denied), admin cross-provider (allowed), and the null-session case.

---

## Reproduction Process

### Environment Setup

I opened the project inside the Docker devcontainer. The MariaDB database runs in the `db` container (database `oscar`) and the app runs on Tomcat 11 at `http://localhost:8080/carlos`. I built and deployed the current `develop` build (`make install`) so I was testing the real, unmodified endpoint. Default dev login: `carlosdoc` / `carlos2026` / PIN `2026` (this account maps to provider `999998`).

### Steps to Reproduce

This is a runtime authorization bug, so reproducing it means logging in as one provider and successfully writing a **different** provider's settings. Attacker = `carlosdoc` (provider `999998`); victim = provider `1` (which starts with no saved settings).

1. Log in at `http://localhost:8080/carlos/index` as `carlosdoc` / `carlos2026` / PIN `2026`.
2. Open the browser Developer Tools Console (right-click the page → Inspect → Console tab).
3. Paste and run (note the victim number `1` in the URL):
   ```js
   fetch("/carlos/ws/rs/providerService/settings/1/save", {
     method: "POST",
     headers: { "Content-Type": "application/json" },
     credentials: "include",
     body: JSON.stringify({
       startHour: 3,
       endHour: 21,
       period: 45,
       faxNumber: "666-IDOR-EXPLOIT",
       rxAddress: "HACKED-BY-999998",
       defaultServiceType: "no",
       rxInteractionWarningLevel: "0",
     }),
   })
     .then((r) => r.text())
     .then((t) => console.log("RESPONSE:", t));
   ```
4. The console prints `RESPONSE: {... "status":"SUCCESS"}` — provider 1's settings were changed while logged in as 999998.

### Reproduction Evidence

- **Fork:** (https://github.com/makter20/carlos)
- **My findings:**
  - The save request returned HTTP `200` with body `{"...","status":"SUCCESS"}`, even though the logged-in provider (999998) has no ownership of or admin rights over provider 1.
  - Provider 1 had **no** settings before the attack. Afterward the `property` table contained the attacker-controlled values:
    ```
    rxAddress   HACKED-BY-999998
    faxnumber   666-IDOR-EXPLOIT
    ```
  - I also confirmed the missing check at the bytecode level: `javap -p -c` on the deployed `ProviderService.class` shows `saveProviderSettings` calling `updateProviderSettings(...)` directly, with no reference to `SecurityInfoManager` or `hasPrivilege`.
  - After testing I cleaned up the injected rows (`DELETE FROM property ...` / `DELETE FROM providerpreference WHERE provider_no='1'`).

---

## Solution Approach

### Analysis

The root cause is that authorization is missing at every layer of this flow, and the target identity is taken from untrusted input:

1. `ProviderService.saveProviderSettings` uses the `{providerNo}` path parameter as the identity of the record to write, instead of the caller's session identity.
2. Neither the REST method nor `ProviderManager2.updateProviderSettings` calls `SecurityInfoManager.hasPrivilege(...)`, so a logged-in-but-unauthorized user is never stopped.
3. The `WARN`-level log of the whole settings object dumps provider configuration into the logs, which the project standards forbid for sensitive/PHI-adjacent data.

The sibling read endpoint `getProviderSettings()` already does the safe thing — it scopes to `getLoggedInInfo().getLoggedInProviderNo()` rather than a path parameter — so the save path just needs to be brought in line with it.

### Proposed Solution

1. Take the caller's identity from the **session** (`getLoggedInProviderNo()`), never from the URL.
2. Allow the write when the caller is editing their own record; otherwise require `_admin` write via `SecurityInfoManager.hasPrivilege(...)`. The self-check fails closed if the session provider is null.
3. On denial, throw `SecurityException("missing required sec object (_admin)")` — the project's paren form, with **no** `providerNo` or settings payload echoed back to the client.
4. Remove the `WARN` log of the settings object.
5. Defense in depth: apply the same self-or-admin check inside `ProviderManager2.updateProviderSettings` so the authorization travels with the operation for any future caller, and record a sanitized audit entry (target `providerNo` only, no settings values) via `LogAction.addLogSynchronous`.

### Implementation Plan

Using UMPIRE framework (adapted):

**Understand:** `saveProviderSettings` lets any authenticated session write any provider's settings because it trusts the `{providerNo}` path parameter and performs no privilege check. The fix must keep normal self-service saves working while blocking cross-provider writes for non-admins.

**Match:** The codebase already has the patterns I need. `PersonaService.updatePreference` (around line 435) guards a preference save with `securityInfoManager.hasPrivilege(getLoggedInInfo(), "_pref", "u", null)` and derives the provider from the session rather than a path parameter. `ProviderManager2` already injects `SecurityInfoManager` and uses `_admin.lab`/`_admin.hrm` write checks around line 699, and already audits with `LogAction.addLogSynchronous` (line 694). I follow the same conventions.

**Plan:**

1. In `ProviderService.java`, inject `SecurityInfoManager` and import `LoggedInInfo`.
2. Rewrite `saveProviderSettings`: read `getLoggedInInfo().getLoggedInProviderNo()`; allow when it equals the path `providerNo`; otherwise require `hasPrivilege(loggedInInfo, "_admin", SecurityInfoManager.WRITE, null)`; on failure throw `SecurityException("missing required sec object (_admin)")`. Remove the `MiscUtils.getLogger().warn(json.toString())` line.
3. In `ProviderManager2.updateProviderSettings`, add the same self-or-admin check at the top (defense in depth) and a sanitized `LogAction.addLogSynchronous(loggedInInfo, "ProviderManager.updateProviderSettings", providerNo)` audit entry.
4. Add a `ProviderService` unit test class covering: self-edit succeeds, cross-provider without `_admin` throws and never calls the manager, admin cross-provider succeeds, and null-session fails closed.

**Implement:** (https://github.com/makter20/carlos/tree/fix/issue-2821-provider-settings-idor)

**Review:** [Self-review checklist - does it follow the project's contribution guidelines?]

**Evaluate:** [How will you verify it works?]

---

## Testing Strategy

### Unit Tests

- [ ] Test case 1: [Description]
- [ ] Test case 2: [Description]
- [ ] Test case 3: [Description]

### Integration Tests

- [ ] Integration scenario 1
- [ ] Integration scenario 2

### Manual Testing

[What you tested manually and results]

---

## Implementation Notes

### Week [X] Progress

[What you built this week, challenges faced, decisions made]

### Week [Y] Progress

[Continue documenting as you work]

### Code Changes

- **Files modified:** [List]
- **Key commits:** [Links to important commits]
- **Approach decisions:** [Why you chose certain approaches]

---

## Pull Request

**PR Link:** [GitHub PR URL when submitted]

**PR Description:** [Draft or final PR description - much of the content above can be adapted]

**Maintainer Feedback:**

- [Date]: [Summary of feedback received]
- [Date]: [How you addressed it]

**Status:** [Awaiting review / Iterating / Approved / Merged]

---

## Learnings & Reflections

### Technical Skills Gained

[What you learned technically]

### Challenges Overcome

[What was hard and how you solved it]

### What I'd Do Differently Next Time

[Reflection on your process]

---

## Resources Used

- [Link to helpful documentation]
- [Tutorial or Stack Overflow post that helped]
- [GitHub issues or discussions that helped]
