# Remediation lifecycle

`clearwing remediate` turns verified sourcehunt findings into separately
reviewable, policy-gated remediation DTOs. It defaults to `report-only`; source
files change only when an operator explicitly selects `--mode apply`.

```text
finding → pre-policy → proposed diff → post-diff policy → independent panel
                                      │
                                      ├─ report-only → proposed / needs_review
                                      │
                                      └─ apply → encrypted backup → git apply
                                                   ├─ validated → keep patch
                                                   └─ failed → exact rollback
```

## Quick start

Generate proposals without modifying the target:

```bash
clearwing remediate run \
  --repo /path/to/project \
  --findings ./results/sourcehunt/sh-example/findings.json \
  --mode report-only
```

Apply only fixes that pass policy and the adversarial panel:

```bash
clearwing remediate policy-init remediation-policy.yaml

clearwing remediate run \
  --repo /path/to/project \
  --findings ./results/sourcehunt/sh-example/findings.json \
  --policy remediation-policy.yaml \
  --mode apply \
  --sandbox-validate \
  --resume
```

When a matching report-only proposal has already passed the panel, apply mode
reuses its encrypted exact diff without asking the remediator to generate a
second patch.

`--sandbox-validate` passes the exact proposed diff to Clearwing's existing
no-network PoC replay sandbox. It is most useful for C/C++ findings with a
recorded PoC. Set `require_dynamic_validation: true` in policy when a patch
must not validate without a successful recompile and replay. Add `--gvisor`
when the `runsc` runtime is installed.

Re-run the independent panel or inspect the workspace:

```bash
clearwing remediate validate \
  --repo /path/to/project \
  --output-dir ./results/remediation/project

clearwing remediate status \
  --output-dir ./results/remediation/project
```

Use `--top N` or repeat `--finding-id ID` to bound a run. Provider flags and
Clearwing's per-task routes work the same way as sourcehunt. Dedicated routes
are `remediator`, `remediation_architect`, `remediation_adversary`, and
`remediation_regression`.

## DTO and checkpoint layout

The output directory is external to the target checkout by default:

```text
results/remediation/<repository>/
  remediation.db
  findings/<finding-id>/<remediation-id>.json
  .artifacts/
    keys/master.key
    remediation/*.enc
    audit.log
```

`remediation.json` is the canonical typed DTO. It records the finding snapshot,
base Git SHA, proposal hash, policy decisions, application hashes, validation
votes, weighted host verdict, timestamps, and terminal status. Human-readable
DTO fields are redacted. The exact patch and pre-application file bytes are
AES-256-GCM encrypted so resume and rollback do not have to persist secrets in
plaintext.

The SQLite index maps a stable fingerprint—repository identity, finding,
target commit, and policy hash—to its DTO. Distinct target revisions retain
distinct DTO history. `--resume` skips complete work, continues an `applied`
checkpoint only when target hashes still match, and refuses automatic recovery
when the checkout changed independently.

## Policy and kill switch

The host owns every policy decision. Model output cannot waive a gate. The
generated default policy supports:

- severity and CWE allow/deny rules;
- minimum evidence and independent-verification requirements;
- target-file-only patches;
- forbidden paths such as `.git/` and `.github/workflows/`;
- maximum files and changed lines;
- fail-closed rejection of file creation/deletion;
- clean-target requirements;
- validation threshold and mandatory dynamic replay;
- automatic rollback after validation failure.

The kill switch is evaluated before generation, after diff parsing, and again
immediately before mutation. Either condition disables remediation:

```bash
export CLEARWING_REMEDIATION_DISABLED=1
touch /path/to/project/.clearwing-remediation-off
```

Both names can be changed in the policy file.

## Independent validation panel

Three isolated calls review the same bounded packet without sharing reasoning:

| Persona | Primary concern |
|---|---|
| Security architect | Root cause, invariant, and design correctness |
| Penetration tester | Bypasses, variants, and residual exploitability |
| Regression reviewer | Safe behavior, API compatibility, and minimality |

The host—not a model—aggregates four gates: root cause (35%), bypass resistance
(30%), regression safety (20%), and minimality (15%). Root cause, bypass
resistance, and regression safety are mandatory. The default total threshold is
0.80. Missing reviewers, malformed responses, insufficient dynamic evidence,
or a score below threshold produce `needs_review`; explicit mandatory-gate,
policy, or dynamic failures produce `validation_failed`.

In apply mode, anything short of `validated` is rolled back by default. A
validated patch remains as an unstaged working-tree change for human review and
commit. Clearwing never commits or pushes target-repository changes from this
workflow.

## Safety boundaries

- The target must be a Git repository root.
- Candidate patches must be unified diffs with safe repository-relative paths.
- Binary patches, renames, mode changes, symlink targets, and file
  creation/deletion are rejected by default.
- The repository HEAD must still match the commit reviewed for remediation.
- Approved target files must be clean before apply.
- `git apply --check` and strict whitespace validation run before mutation.
- Rollback refuses to overwrite a file changed after Clearwing applied its
  patch.
- Sandbox replay uses the read-only source mount and writable `/scratch`; it
  does not apply the candidate to the host checkout.
