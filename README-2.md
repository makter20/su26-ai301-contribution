# Contribution Log

# Contribution [#2821]: Add authorization to provider settings save (fix IDOR)

**Contribution Number:** 2  
**Student:** Mahmuda Akter  
**Issue:** https://github.com/carlos-emr/carlos/issues/2821
**Fork Link:** (https://github.com/makter20/carlos)
**Status:** Phase II — implemented, unit-tested, and validated live on a local dev build (commit `978b60ae2d`); not yet pushed / no PR opened

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
2. Open the browser Developer Tools Console (right-click the page -> Inspect -> Console tab).
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

The fix was implemented on branch `fix/issue-2821-provider-settings-idor` in three files:

- `ProviderService.java` — injected `SecurityInfoManager`, imported `LoggedInInfo`, rewrote `saveProviderSettings` to derive identity from the session and enforce self-or-`_admin`, and removed the `WARN` settings log.
- `ProviderManager2.java` — added the same self-or-admin guard at the top of `updateProviderSettings` (defense in depth) plus a sanitized `LogAction.addLogSynchronous(loggedInInfo, "ProviderManager.updateProviderSettings", providerNo)` audit entry (target provider only, no settings values).
- `ProviderServiceUnitTest.java` — new unit test covering the four authorization branches.

One deviation from the original plan: I planned to add the audit via `OscarLogManager`, but that interface is query-only (it just reads "recent demographics viewed") and has no audit-write method. The correct, idiomatic tool is `LogAction.addLogSynchronous`, which the sibling `updateProvider` method already uses, so I used that instead.

**Review:** Self-review against the project's contribution guidelines:

- [x] Authorization via `SecurityInfoManager.hasPrivilege(...)` on every write path (REST + manager).
- [x] `SecurityException` message uses the paren form `missing required sec object (_admin)` and leaks no `providerNo` or payload to the client.
- [x] No PHI / PHI-adjacent data written to logs (removed the `WARN` settings dump; the audit records only the target provider number).
- [x] New namespace (`io.github.carlos_emr.carlos.*`) and layer/name conventions preserved.
- [x] Unit tests follow the JUnit 5 + BDD naming convention and reuse the existing `EFormServiceUnitTest` harness style.
- [x] No parameterized-query / path-traversal surface changed (none in this flow).
- [ ] Open decision: denial currently surfaces as HTTP 500 (thrown `SecurityException`); a 403 would be cleaner REST semantics — see Learnings.

**Evaluate:** Verified by (a) rebuilding and redeploying the fixed build and re-running the exact live exploit — it is now blocked with no database change, while a legitimate self-save and a legitimate admin save both still succeed; and (b) the new unit tests, which pass and were confirmed meaningful with a manual mutation check (see Testing Strategy).

---

## Testing Strategy

### Unit Tests

New class: `src/test/java/io/github/carlos_emr/carlos/webserv/rest/ProviderServiceUnitTest.java` (JUnit 5, Mockito, extends `CarlosUnitTestBase`; testable subclass overrides `getLoggedInInfo()` and injects mocked `ProviderManager2` / `SecurityInfoManager`). All four pass (`tests=4, failures=0, errors=0`):

- [x] `shouldSaveSettings_whenProviderEditsOwnSettings` — caller edits their own provider number; the manager is invoked (self-service still works).
- [x] `shouldThrowSecurityException_whenNonAdminEditsAnotherProvider` — non-admin targets another provider; throws `SecurityException` and the manager is **never** called (the IDOR is blocked).
- [x] `shouldSaveSettings_whenAdminEditsAnotherProvider` — caller with `_admin` write targets another provider; allowed by design.
- [x] `shouldThrowSecurityException_whenSessionProviderIsNull` — no session provider; fails closed (throws, manager never called).

**Mutation sanity check:** I temporarily disabled the authorization guard in the production code and re-ran the suite. The two deny-path tests failed (`tests=4, failures=2`) while the two allow-path tests still passed, and re-enabling the guard returned all four to green. This confirms the tests genuinely assert the security behavior rather than passing trivially.

### Integration Tests

- [x] End-to-end HTTP validation on a running Tomcat + MariaDB build (documented under Manual Testing). This covers the real routing (`/ws/rs`), the `AuthenticationInInterceptor` session gate, and the database effect.
- [ ] No automated (in-repo) integration test was added. The endpoint's session/authorization behavior is exercised manually and by the unit tests; an automated CXF-level integration test is a possible follow-up.

### Manual Testing

I validated before and after the fix on a real deployed build (attacker = provider 999998, victim = provider 1):

| Scenario             | Account                  | Request                     | Vulnerable build                 | Fixed build                                                      |
| -------------------- | ------------------------ | --------------------------- | -------------------------------- | ---------------------------------------------------------------- |
| Attack (the IDOR)    | non-admin 999998         | `POST settings/1/save`      | HTTP 200, provider 1 overwritten | **HTTP 500 / SecurityException, provider 1 unchanged (blocked)** |
| Legitimate self-save | 999998                   | `POST settings/999998/save` | HTTP 200                         | **HTTP 200 SUCCESS**                                             |
| Admin edits another  | 999998 with `admin` role | `POST settings/1/save`      | HTTP 200                         | **HTTP 200 SUCCESS (allowed by design)**                         |

To test the non-admin deny path I temporarily removed carlosdoc's `admin` role (the dev account has both `doctor` and `admin`), then restored it afterward. All injected test data on provider 1 was cleaned up.

---

## Implementation Notes

### Code Changes

- **Files modified:**
  - `src/main/java/io/github/carlos_emr/carlos/webserv/rest/ProviderService.java`
  - `src/main/java/io/github/carlos_emr/carlos/managers/ProviderManager2.java`
  - `src/test/java/io/github/carlos_emr/carlos/webserv/rest/ProviderServiceUnitTest.java` (new)
- **Key commit:** `978b60ae2d` — "fix: add authorization to provider settings save (IDOR)" (3 files changed, +211/-2) on branch `fix/issue-2821-provider-settings-idor`.
- **Approach decisions:**
  - Identity is taken from the session, never the URL path — the path `providerNo` is treated as the target, and the caller must own it or be an admin.
  - Reused the existing `_admin` write privilege and the `hasPrivilege` pattern already used elsewhere in `ProviderManager2`, rather than inventing a new security object.
  - Added the check in both the REST action and the manager so a future caller of the manager cannot reintroduce the IDOR.
  - Used `LogAction.addLogSynchronous` for the audit (not `OscarLogManager`, which is query-only), matching the sibling `updateProvider` audit.

### Remaining before opening the PR

- Run the full unit suite (`make install --run-unit-tests`) and confirm CI checks are green (only the focused test was run so far).
- Push the branch and open the PR against `develop`.

---

## Pull Request

**PR Link:** Not yet opened (branch committed locally; push pending).

**PR Description (draft):**

> **fix: add authorization to provider settings save (IDOR) — fixes #2821**
>
> `ProviderService.saveProviderSettings` accepted the target `providerNo` from the URL path and saved settings for that provider with only a login check, so any authenticated session could overwrite any provider's settings (IDOR). It also logged the full settings object at `WARN`.
>
> This change:
>
> - derives the caller identity from the session (`getLoggedInProviderNo()`), never the request path;
> - allows a provider to edit only their own settings, and requires `_admin` write (`SecurityInfoManager.hasPrivilege`) to edit another provider's settings, failing closed on a null session and denying with a paren-form `SecurityException` that leaks no identifiers;
> - removes the `WARN` log of the settings object;
> - applies the same check inside `ProviderManager2.updateProviderSettings` (defense in depth) with a sanitized `LogAction` audit;
> - adds `ProviderServiceUnitTest` covering self-edit (allowed), non-admin cross-provider (denied), admin cross-provider (allowed), and null-session (fails closed).
>
> Validated live: the exploit is now blocked with no DB change, while legitimate self-service and admin saves still succeed.

**Maintainer Feedback:**

- [Date]: [Summary of feedback received]
- [Date]: [How you addressed it]

**Status:** Not yet submitted — local commit ready, push and PR pending.

---

## Learnings & Reflections

### Technical Skills Gained

- Recognizing and fixing an IDOR: the core lesson is to derive the acted-on identity from the authenticated session, not from client-supplied input, and to enforce ownership/role at every layer.
- How CARLOS wires its REST layer: CXF JAX-RS services under `/ws/rs`, the `AuthenticationInInterceptor` session gate, the OAuth interceptor's session fallback, and how CSRFGuard's unprotected-page config (`/ws/*`) affects reachability.
- Using the project's `SecurityInfoManager.hasPrivilege` authorization model and its security objects (e.g. `_admin`).
- Verifying a fix at multiple levels: reading bytecode with `javap`, live HTTP before/after testing against a real DB, focused JUnit 5 + Mockito unit tests, and a manual mutation check to prove the tests are meaningful.

### Challenges Overcome

- The pre-deployed webapp was stale and failed to start (missing `Owasp.CsrfGuard.properties`); I had to rebuild/redeploy to get a faithful target.
- Finding the real endpoint path: the services are served under `/ws/rs`, while `/ws/services` is only CXF's listing page.
- The default dev account (`carlosdoc`) has both `doctor` and `admin` roles, so it was authorized under the fix — I had to temporarily reduce it to a non-admin role to prove the deny path, then restore it.
- A hot-reload watcher started by `make install` corrupted incremental compilation of the tests; stopping it and doing a clean compile resolved it.

### What I'd Do Differently Next Time

- Decide the denial HTTP semantics up front. The fix throws `SecurityException`, which surfaces as HTTP 500; a 403 Forbidden would be cleaner for an authorization failure, though 500 matches how other CARLOS REST services signal denials today.
- Consider an automated integration test for the endpoint's auth, so the live validation I did by hand is captured in CI.

---

## Resources Used

- CARLOS `CLAUDE.md` — security requirements (`SecurityInfoManager.hasPrivilege`, paren-form `SecurityException`, no PHI in logs) and the test-writing conventions.
- Existing code patterns: `PersonaService.updatePreference` (session-scoped, privilege-checked save) and `EFormServiceUnitTest` (REST unit-test harness).
- OWASP — Insecure Direct Object Reference (IDOR) and CWE-639 (Authorization Bypass Through User-Controlled Key).
- GitHub issue #2821.
