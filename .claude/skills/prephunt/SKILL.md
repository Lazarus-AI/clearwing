---
name: prephunt
description: Research a CVE and fill in a structured task YAML entry for the sourcehunt eval. Given a semi-filled YAML block, queries NVD/GHSA, clones the repo, inspects fix/vulnerable commits, and completes the missing fields.
argument-hint: <partial YAML block pasted in conversation>
---

# Prephunt

You are completing a structured vulnerability task entry for the clearwing sourcehunt evaluation benchmark. The user provides a **partially-filled YAML block** in the conversation. Your job is to research the CVE and fill in whatever is missing or null, and rewrite the `description` with a proper technical explanation grounded in the CVE database and the actual code diff.

## Input

The user provides a YAML block like this in the conversation (fields may be null, empty lists, or placeholder text):

```yaml
- cve: CVE-2026-47345
  repo: TYPO3/html-sanitizer
  clone_url: https://github.com/TYPO3/html-sanitizer.git
  language: PHP
  vulnerable_commit: null
  fix_commit: 8b5d0be44ded457ca993ec9ca93d859941c63764
  files: []
  vuln_class: null
  title: typo3/html-sanitizer namespace-attr XSS bypass.
  severity: Medium
  difficulty: easy
  description: typo3/html-sanitizer namespace-attr XSS bypass.
  judge_signal:
    files: []
    symbols: []
    keywords: []
```

**What counts as "already filled":** A field is considered provided if it has a non-null, non-empty value that isn't just repeating the title. Preserve these values unless your research contradicts them — in that case, flag the discrepancy to the user.

**What to fill in:** Any field that is `null`, an empty list `[]`, or a placeholder (e.g. description that just repeats the title). Always rewrite `description` with a proper technical explanation regardless.

If no YAML block is in the conversation, ask for one and stop.

## Output schema

The completed YAML block uses exactly these fields:

```yaml
- cve: CVE-XXXX-XXXXX
  repo: org/repo
  clone_url: https://github.com/org/repo.git
  language: <primary language of affected code>
  vulnerable_commit: <full SHA — a commit containing the vulnerable code, before the fix>
  fix_commit: <full SHA — the commit that patches the vulnerability>
  files:
    - <path(s) modified in the fix commit>
  vuln_class: >-
    CWE-XX <name> (<brief mechanistic description>)
  title: >-
    <project>: <concise vulnerability title>
  severity: <Critical|High|Medium|Low (include CVSS if available)>
  difficulty: <easy|medium|hard>
  description: >-
    <Technical description: what the vulnerable code does wrong, why it's exploitable,
    what the attack path is, and what the fix changes. Reference specific function names,
    variables, and file paths. 3-6 sentences.>
  judge_signal:
    files:
      - <file(s) a hunter would need to read>
    symbols:
      - <function names, type names, error variants, key variables>
    keywords:
      - <domain phrases a hunter's report should mention to prove understanding>
```

## Workflow

### Phase 1: Parse input and identify gaps

1. Parse the user's YAML block. Note which fields are already provided and which need filling.
2. Extract the CVE ID — this drives all subsequent lookups.
3. Note pre-filled values (repo, clone_url, fix_commit, language, severity, difficulty, title) — these are your starting anchors.

### Phase 2: External lookup

1. Query the NVD API:
   ```
   curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE-ID>" | python3 -m json.tool
   ```
   Extract: description, CVSS score/severity, CWE, affected packages/versions, and all reference URLs.

2. Check references for GitHub Security Advisories (GHSA). If found, fetch with:
   ```
   gh api /repos/<owner>/<repo>/security-advisories --jq '.[] | select(...)'
   ```
   Or use WebFetch on the GHSA URL.

3. Look for commit URLs in the references. NVD references often link to fix commits or the commit that introduced the vuln — **do not assume they are correctly labeled**. You will verify them in Phase 3.

4. If no CVE is found in NVD, warn the user:
   > ⚠️ CVE not found in NVD. This may be reserved, rejected, or too new. Proceeding with any available GHSA/web sources.

### Phase 3: Repo + commit verification

1. Use the `clone_url` from the input (or identify from advisory references if missing).

2. Clone blobless into /tmp:
   ```
   cd /tmp && rm -rf prephunt-repo && git clone --bare --filter=blob:none <clone_url> prephunt-repo
   ```

3. If `fix_commit` is provided, verify it exists and inspect it:
   ```
   git cat-file -t <sha>
   git log --oneline <sha> -1
   git diff-tree --no-commit-id --name-only -r <sha>
   ```

4. If `fix_commit` is null, **identify it.** Strategies (try in order):
   - If a reference commit message says "fix" / "patch" / "security" and touches the relevant file → likely the fix.
   - If the advisory names patched versions, find the version tag and look for commits touching the affected file between the prior version tag and the patched tag:
     ```
     git log --oneline <prev-tag>..<patched-tag> -- <file>
     ```
   - Read the diff of candidate commits and confirm it removes the vulnerable pattern described in the advisory.

5. If `vulnerable_commit` is null, **identify it.** Strategies:
   - The commit that *introduced* the vulnerable code (ideal — find via `git log --diff-filter=A -- <file>` or from the advisory).
   - If unclear, pick the fix commit's immediate parent (`<fix>~1`) — it definitely contains the vuln.
   - Verify: `git show <vulnerable_commit>:<file>` should contain the vulnerable pattern.

6. Confirm ancestry: `git merge-base --is-ancestor <vulnerable> <fix>` must be true.

### Phase 4: Diff analysis

1. List changed files (fills the `files` field):
   ```
   git diff-tree --no-commit-id --name-only -r <fix_commit>
   ```

2. Read the full fix diff:
   ```
   git diff <fix_commit>^..<fix_commit>
   ```

3. From the diff, identify:
   - **What was wrong** — the vulnerable code pattern (function, logic flaw, missing check)
   - **What the fix does** — the new guard, validation, or refactoring
   - **Symbols** — function names, struct/enum variants, error types, key variables (both old and new)
   - **Keywords** — domain-specific phrases that demonstrate understanding of the bug

4. Cross-check NVD reference commits against what you found:
   - Are the NVD-listed commits actually the fix, the introduction of the vuln, or something unrelated?
   - Report any discrepancies to the user.

### Phase 5: Complete the YAML

Fill in all missing fields. Guidelines:

- `description`: **Always rewrite**, even if one was provided. Explain the mechanism grounded in the actual diff and CVE description. Name the function, describe the flaw, describe the attack path, describe the fix. A security engineer reading this should understand the bug without looking at the code. 3-6 sentences.
- `vuln_class`: Start with the CWE number and name, then add a parenthetical mechanistic note.
- `title`: Keep the user's title if provided and accurate. Otherwise: `<project> <component>: <what goes wrong> via <attack vector>`
- `severity`: Keep the user's value if consistent with CVSS. Otherwise note the discrepancy.
- `difficulty`: Keep the user's value. Only flag if your analysis suggests otherwise.
- `files`: From `git diff-tree` on the fix commit that are relevant to the vulnerability.
- `judge_signal.files`: Same as `files` unless additional files are needed for context.
- `judge_signal.symbols`: Include symbols from BOTH the vulnerable code (what a hunter would find) and the fix (proves they found the right thing). Aim for 4-8 symbols.
- `judge_signal.keywords`: Domain phrases that demonstrate understanding, not just function names. Aim for 5-8 keywords.

### Phase 6: Corroboration report

Present the completed YAML to the user along with a corroboration table:

| Field | Source | Confidence |
|-------|--------|------------|
| `fix_commit` | provided by user / GHSA / tag analysis | High/Medium/Low |
| `vulnerable_commit` | derived as fix~1 / advisory / introduced-in | High/Medium/Low |
| `files` | `git diff-tree` on fix commit | High |
| `vuln_class` | NVD CWE field | High/Medium |
| ... | ... | ... |

Flag any field where:
- External sources disagree with each other
- The NVD references point to wrong/unrelated commits
- A user-provided value contradicts what you found
- A field is inferred rather than externally corroborated

Provide the CVE DB entry URL, as well as the github diff for the fix commit. Update evaluations/cves.yaml with your corrected entry. Then create a shell script to run a sourcehunt as defined by the pattern in evaluations/cve*.sh. Ask the user to confirm or investigate uncertain fields before finalizing.

## Important notes

- **Preserve user-provided values** unless your research contradicts them. When contradicted, show both and ask.
- **Do not trust NVD reference commits blindly.** They are frequently wrong (pointing to the commit that introduced the vuln, or unrelated merges). Always verify by reading the diff.
- **The vulnerable_commit must contain the vulnerable code.** Verify with `git show <sha>:<file>` and confirm the vulnerable pattern is present.
- **The fix_commit must remove/correct the vulnerable code.** Verify with the diff.
- **Ancestry matters.** `vulnerable_commit` must be an ancestor of `fix_commit`.
- **Clone into /tmp** to avoid polluting the working directory.
- **Be interactive.** If something is ambiguous (multiple candidate fix commits, unclear which file is affected), ask the user rather than guessing.
- **Description is always rewritten.** The input description is often just a placeholder or title repeat. Ground the new description in the NVD text and the actual code diff.
