# CyberPi blind CVE evaluation

This evaluation compares the native Sourcehunt loop with CyberPi at the
existing per-file hunt-engine boundary. It is intentionally narrower than a
full repository Sourcehunt evaluation: ranking, verification, and reporting
are held outside the experiment so the harnesses receive the same assignment,
prompt, source context, tools, model, turn limit, and output-token limit.

## Corpus and split

The packaged declarative suites are:

- `tuning-cves`: CVE-2026-28208 (Junrar, CWE-22) and CVE-2026-47391
  (PraisonAI, CWE-95/CWE-306).
- `held-out-cves`: CVE-2026-27775 (Gitea, CWE-863/CWE-862) and
  CVE-2026-40033 (FreeRDP, CWE-787/CWE-122).

Each case pins a vulnerable commit and a reviewed fixed commit. The fixed
snapshot is the matched safe negative. The split is repository-disjoint and
was frozen before any prompt experiment. `corpus-lock.json` records the full
digest of every source export and target file observed on 2026-08-13.

The fixes and labels were verified from NVD and the upstream commits or pull
requests referenced in the suite files. They are grading data, not model
context.

## Blindness contract

The snapshot materializer fetches a pinned commit into a private bare cache and
exports only the declared source subtree. Git metadata is never exported. The
hunter's `read_file` tool is confined to that exported subtree; `execute` is
disabled for this source-only experiment. The model receives the assigned file
and source-root inventory, but never receives:

- the CVE ID, vulnerable/fixed label, commit ID, suite role, or case ID;
- an advisory, patch, commit message, reference, or grading anchor;
- the alternate snapshot or Clearwing's evaluation manifests.

The grader runs only after a trajectory is sealed. This separation is tested.
Fixed-source comments remain part of the real patched negative; no synthetic
cleanup is applied to make the negative easier.

## Protocol

Use tuning cases for prompt or tool experiments. Change one variable at a time
and run at least three replicates, alternating engine and snapshot order. Select
one candidate before opening the held-out suite, then run the held-out suite at
least five times for a promotion decision.

```bash
clearwing cyberpi benchmark \
  --suite tuning-cves \
  --runs 3 \
  --max-turns 8

clearwing cyberpi benchmark \
  --suite held-out-cves \
  --runs 5 \
  --max-turns 8
```

The aggregate report includes vulnerable recall, fixed-snapshot false-positive
rate, acceptable-CWE accuracy, source-location accuracy, evidence-anchor
coverage, total/mean tokens, latency, errors, majority-decision stability, and
pairwise finding-signature stability. A detection requires both source
grounding and at least half of the case's independently defined causal evidence
groups; a guessed CWE alone is not recall.

Every JSONL trajectory contains the exact prompt, initial message, complete
Clearwing-owned tool definitions, assistant text/reasoning, tool calls/results,
usage, and final findings. The publisher sanitizes configured credentials and
authorization/user-info patterns in place, records a SHA-256 digest and
redaction count, and refuses an artifact if the configured inference credential
remains.

## Promotion rule

Do not create or promote a CyberPi profile from tuning results alone. A
candidate must improve held-out recall or evidence quality on repeated runs,
must not materially worsen fixed-snapshot false positives or stability, and
must report its token/latency tradeoff. Until such evidence exists, native
Clearwing remains unchanged and no `CyberPiProfile` abstraction is justified.

## Environment result (2026-08-13)

All eight repository snapshots fetched and reproduced the digests in
`corpus-lock.json`. Node 26.7.0 and the pinned Pi 0.84.1 runtime are installed.
Docker is not installed, so Docker-backed repository Sourcehunt E2E could not
run. No inference credential was available to this session; consequently no
paid-model result or CyberPi profile is claimed, and no synthetic result is
substituted for the missing DeepSeek-v4-Flash-0731 experiment.
