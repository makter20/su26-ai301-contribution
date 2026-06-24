# Contribution [#2935]: Replace timing-sensitive lab hash comparison in duplicate detection

**Contribution Number:** 1  
**Student:** Mahmuda Akter  
**Issue:** https://github.com/carlos-emr/carlos/issues/2935
**Fork Link:** (https://github.com/makter20/carlos)
**Status:** Phase I

---

## Why I Chose This Issue

I am always passionate about the healthcare field. I have a plan to shift my career toward Data Analysis in healthcare. Because of my passion for healthcare, I chose this issue. I have experience in full stack development. I hope to learn how the work is done in a real healthcare company.

---

## Understanding the Issue

### Problem Description

This issue flagged a security weakness in the duplicate-detection logic for lab versions. When the system checks whether a new lab body is a duplicate of an existing one, it compares two SHA-256 hashes using Java's standard `String.equals()`. The problem is that `String.equals()` is timing sensitive it returns as soon as it finds the first character that differs, so the time it takes to run leaks information about how many leading characters of the two hashes match. This pattern violates the project's `UNSAFE_HASH_EQUALS` rule. The fix is to compare the hashes in constant time so the comparison always takes the same amount of time regardless of where or whether they differ.

### Expected Behavior

The hash comparison should be done with a constant time method such as `MessageDigest.isEqual()` instead of `String.equals()`. The change must:

1. Replace the unsafe comparison with a constant-time equivalent.
2. Preserve the exact same duplicate-detection behavior (matching hashes are still treated as duplicates; non-matching hashes are not).
3. Add or extend tests that cover both the matching and non-matching lab-body cases.

### Current Behavior

The comparator currently uses string equality — roughly `String.equals()` to decide whether two lab versions are duplicates. This works functionally, but because `String.equals()` short-circuits on the first differing character, it is timing-sensitive and triggers the `UNSAFE_HASH_EQUALS` security rule.

### Affected Components

- **`src/main/java/io/github/carlos_emr/carlos/lab/ca/all/util/LabVersionComparator.java`** (line 63) — the `LabVersionComparator` class in function `isLabDuplicate(String currentSegmentID)` where the SHA-256 hashes are compared.
- The unit tests for `LabVersionComparator`, which will need new cases for matching and non-matching lab bodies.

---

## Reproduction Process

### Environment Setup

I did not run into much trouble setting things up. I opened the project inside a Docker container. The first time I tried, it would not open, and it took me a little while to realize my Docker Desktop was outdated. Once I updated Docker Desktop, everything worked and I was able to run the image without any issues.

### Steps to Reproduce

This is a static analysis security alert rather than a runtime bug, so reproducing it means confirming the unsafe comparison and the alert that flags it.

1. Open the flagged file `src/main/java/io/github/carlos_emr/carlos/lab/ca/all/util/LabVersionComparator.java` and go to line 63 inside the `isLabDuplicate(String currentSegmentID)` method.
2. Confirm that the two SHA-256 hashes are compared with `labHash.equals(currentLabHash)`, which uses Java's timing sensitive `String.equals()` instead of a constant time method.
3. Open the suppression file .github/spotbugs/spotbugs-exclude.xml and comment out the two LabVersionComparator blocks around lines 547–556. (The warning is currently hidden by these — that's why we have to turn it off to see it.)

4. Run the scanner in container:
   `mvn -B compile spotbugs:spotbugs -Pspotbugs`
   Check the result:
   `grep UNSAFE_HASH_EQUALS target/spotbugs-result.xml`
   This is will show the UNSAFE_HASH_EQUALS at LabVersionComparator, that is how the issue reproduced.
   With this following command `grep UNSAFE_HASH_EQUALS target/spotbugs-result.xml` I see output `2` in the terminal which ensured that issue is produced.

### Reproduction Evidence

- **Commit showing reproduction:** (https://github.com/makter20/carlos)
- **Screenshots/logs:** [If applicable]
- **My findings:**
  During the issue reproduction I found the following log message by running the following command `grep -B2 -A6 UNSAFE_HASH_EQUALS target/spotbugs-result.xml`. This is the output: "</Details></BugPattern><BugPattern cweid='203' abbrev='SECUHE' category='SECURITY' type='UNSAFE_HASH_EQUALS'><ShortDescription>Unsafe hash equals</ShortDescription><Details>

&lt;p&gt;
An attacker might be able to detect the value of the secret hash due to the exposure of comparison timing. When the
functions &lt;code&gt;Arrays.equals()&lt;/code&gt; or &lt;code&gt;String.equals()&lt;/code&gt; are called, they will exit earlier if fewer
bytes are matched."

---

## Solution Approach

### Analysis

The root cause is on three lines of isLabDuplicate(String currentSegmentID) method in LabVersionComparator.java:

1. Line 53 and line 62 produce the two hashes as hex strings using DigestUtils.sha256Hex(...).
2. Line 63 compares them with labHash.equals(currentLabHash).
3. Because String.equals() compares character-by-character and returns as soon as it finds a mismatch, its execution time depends on how many leading characters match. Find Security Bugs flags this as UNSAFE_HASH_EQUALS (CWE-203). The data here is a SHA-256 of HL7 lab content rather than a secret credential, so the practical risk is low — but the project standard is to compare hash values in constant time, so the correct resolution is to fix the comparison (not suppress it).

### Proposed Solution

Compare the hashes as raw bytes in constant time using java.security.MessageDigest.isEqual(). The cleanest way is to compute the digest as a byte[] with DigestUtils.sha256(...) instead of the hex string DigestUtils.sha256Hex(...), then compare the byte arrays. This removes the timing leak and avoids any hex decoding step, while keeping the duplicate-detection logic identical.

### Implementation Plan

Using UMPIRE framework (adapted):

**Understand:** LabVersionComparator.isLabDuplicate decides if a lab version is a duplicate by comparing SHA-256 hashes of two HL7 bodies with timing-sensitive String.equals(), which triggers the UNSAFE_HASH_EQUALS rule. The fix must keep the exact same duplicate result while comparing in constant time.

**Match:** The codebase already uses this pattern. Login2Action.java:949-950 compares values with MessageDigest.isEqual(...) for constant-time safety. I will follow the same approach, using the raw digest bytes from DigestUtils.sha256(...) as the inputs.

**Plan:**

1. In LabVersionComparator.java, change lines 53 and 62 from DigestUtils.sha256Hex(...) (String) to DigestUtils.sha256(...) (byte[]).
2. Change line 63 from labHash.equals(currentLabHash) to MessageDigest.isEqual(labHash, currentLabHash).
3. Add import java.security.MessageDigest;.
4. Remove the now-obsolete suppression: delete the two LabVersionComparator <Match> blocks for UNSAFE_HASH_EQUALS in .github/spotbugs/spotbugs-exclude.xml (lines ~547-556), since the finding no longer exists after the fix.
5. Add a unit test class LabVersionComparatorUnitTest covering duplicate and non-duplicate cases.

**Implement:** (https://github.com/makter20/carlos/tree/fix-issue-2935-lab-hash-timing)

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
