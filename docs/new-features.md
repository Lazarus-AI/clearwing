# New Features & UAT Procedures

Features added in specs 001–018 with happy-path user acceptance testing procedures.

---

## Features Added (specs 001–018 + bug fixes)

### Pipeline Features

| # | Feature | CLI Command | Dependencies |
|---|---------|-------------|--------------|
| 1 | N-day exploit pipeline | `clearwing sourcehunt --nday --cve-list` | Docker, build toolchain |
| 2 | Reverse engineering pipeline | `clearwing sourcehunt --reveng --arch x86_64` | Ghidra, Java |
| 3 | Campaign orchestration | `clearwing campaign run campaign.yaml` | LLM API |
| 4 | Disclosure workflow | `clearwing disclose queue/review/validate/reject/send/status/timeline/verify/commitments` | None |
| 5 | OSS-Fuzz benchmark | `clearwing bench ossfuzz --corpus-dir ... --mode standard` | Docker, LLM API |
| 6 | Preprocessing A/B eval | `clearwing eval preprocessing --project ... --configs ...` | LLM API |

### Sourcehunt Enhancements

| # | Feature | Flag / Config |
|---|---------|---------------|
| 7 | 4-axis validator (REAL/TRIGGERABLE/IMPACTFUL/GENERAL) | `--validator-mode v2` (default) |
| 8 | Findings pool + cross-campaign dedup | `--enable-findings-pool` (default on) |
| 9 | Three-band budget promotion (fast→standard→deep) | `--starting-band`, `--max-band` |
| 10 | Entry-point sharding | `--shard-entry-points` (auto at depth=deep) |
| 11 | Subsystem hunting | `--enable-subsystem-hunt`, `--subsystem-paths` |
| 12 | Agentic exploit development | `--no-exploit` to disable |
| 13 | Exploit elaboration | `--enable-elaboration` |
| 14 | PoC stability verification | Enabled by default with sandbox |
| 15 | Variant loop (sibling bug surfacing) | `--no-variant-loop` to disable |
| 16 | Auto-patcher | `--enable-auto-patch` |
| 17 | Behavioral monitor | `--no-behavior-monitor` to disable |
| 18 | Artifact store (encrypted exploits) | `--enable-artifact-store` |
| 19 | SHA-3 cryptographic commitments | Auto on `root_cause_explained` findings |
| 20 | Severity calibration tracking | `--enable-calibration` (default on) |

### Infrastructure

| # | Feature | Description |
|---|---------|-------------|
| 21 | Streaming support | `on_text_delta` callback, `achat_stream` |
| 22 | Agent protocols (typed) | `LLMInvokable`, `SystemPromptFactory`, etc. |
| 23 | Sandbox hardening | seccomp profiles, gVisor, capability dropping |
| 24 | Provider catalog | Centralized model presets, OpenAI-compat |
| 25 | `clearwing_home()` + env overrides | `CLEARWING_HOME`, `CLEARWING_MAX_FILE_SIZE`, etc. |

### Bug Fixes

| # | Fix | Before → After |
|---|-----|----------------|
| 26 | Port scanner default | `syn` (needs root) → `connect` (works unprivileged) |
| 27 | NVD timeout tracebacks | Multi-frame dump → single-line WARNING |
| 28 | aiohttp session leak | Unclosed session → proper `finally: close()` |
| 29 | Version formatting | `vNone`, `vVercel` → `HTTP (Vercel)`, `HTTP v2.4.41` |
| 30 | Doctor macOS probe | Checks `dtruss` instead of `strace` on Darwin |

---

## Happy-Path UAT Procedures

### 1. N-Day Exploit Pipeline

```bash
# Prereqs: Docker running, LLM API key set
clearwing sourcehunt https://github.com/curl/curl \
    --nday --cve-list CVE-2023-38545 \
    --depth standard --output-dir ./results/nday

# Verify:
# - Vulnerable version built successfully (check logs for "build complete")
# - Exploit attempt ran against vulnerable version
# - Validation ran against patched version
# - Report generated at ./results/nday/sh-*/
ls ./results/nday/sh-*/report.md
```

### 2. Reverse Engineering Pipeline

```bash
# Prereqs: Ghidra installed, GHIDRA_HOME set, Java available
clearwing sourcehunt /path/to/sample-binary \
    --reveng --arch x86_64 --depth standard

# Verify:
# - Ghidra decompilation produced output (check logs for "decompiled N functions")
# - LLM reconstruction produced source files
# - Vulnerability hunter ran on reconstructed source
# - Report generated with hybrid source+binary validation
ls ./results/sourcehunt/sh-*/report.md
```

### 3. Campaign Orchestration

```bash
# Create campaign.yaml with 2-3 small test repos:
cat > /tmp/test-campaign.yaml <<'YAML'
name: test-campaign
budget: 10.0
max_concurrent_containers: 2
targets:
  - repo: https://github.com/antirez/sds
    budget: 5.0
  - repo: https://github.com/DaveGamble/cJSON
    budget: 5.0
YAML

clearwing campaign run /tmp/test-campaign.yaml --output-dir ./results/campaign

# Verify:
# - Both projects attempted (logs show "running" for each)
# - Checkpoint file created
ls ./results/campaign/campaign-*/checkpoint.json
# - Campaign result shows projects_completed=2
# - Budget tracking works (total_cost_usd ≤ 10.0)

# Test pause/resume:
clearwing campaign status ./results/campaign/
```

### 4. Disclosure Workflow

```bash
# Prereqs: Run a sourcehunt first to populate findings
clearwing sourcehunt https://github.com/DaveGamble/cJSON \
    --depth standard --export-disclosures

# Queue findings:
clearwing disclose queue

# Verify: table shows findings with state=pending_review

# Review a finding:
clearwing disclose review <finding-id>
# Verify: full context displayed, state moves to in_review

# Validate:
clearwing disclose validate <finding-id> --reviewer "tester" --notes "confirmed"
# Verify: state moves to validated

# Check commitments:
clearwing disclose commitments
# Verify: SHA-3 commitment entries present

# Verify a commitment:
clearwing disclose verify <finding-id> --document ./results/sourcehunt/sh-*/findings.json

# Timeline check:
clearwing disclose timeline --days 90

# Status dashboard:
clearwing disclose status
# Verify: shows by_state counts, total, approaching_deadlines
```

### 5. OSS-Fuzz Benchmark

```bash
# Create a minimal corpus directory with 2-3 small projects:
mkdir -p /tmp/bench-corpus/test_project
# (copy a small C project with a known crash into test_project/)

clearwing bench ossfuzz \
    --corpus-dir /tmp/bench-corpus \
    --mode quick \
    --model claude-sonnet-4-6

# Verify:
# - Per-target JSON results written
ls ./results/bench/*.json
# - Tier distribution computed (tiers 0-5)
# - Total cost tracked
# - benchmark_quick_*.json has targets_attempted, targets_succeeded

# Compare two models:
clearwing bench compare ./results/bench/benchmark_quick_model_a.json \
                        ./results/bench/benchmark_quick_model_b.json
```

### 6. Preprocessing A/B Eval

```bash
clearwing eval preprocessing \
    --project https://github.com/DaveGamble/cJSON \
    --configs glasswing_minimal,sourcehunt_full \
    --runs 1 \
    --depth quick \
    --budget 5.0

# Verify:
# - Per-config directories created
ls ./results/eval/glasswing_minimal/run_0.json
ls ./results/eval/sourcehunt_full/run_0.json
# - Metrics computed (findings_total, cost_usd, cwe_diversity)
# - eval_*.json aggregates both configs with mean/stddev

# Compare results:
clearwing eval compare ./results/eval/eval_*.json
```

### 7. 4-Axis Validator

```bash
# Runs automatically during sourcehunt verify stage:
clearwing sourcehunt https://github.com/DaveGamble/cJSON \
    --depth standard --validator-mode v2

# Verify in output:
# - Logs show "Validator" calls per finding
# - Report shows 4-axis verdicts (REAL:pass/fail, etc.)
# - Findings with advance=false are in rejected list
grep -i "REAL\|TRIGGERABLE\|IMPACTFUL\|GENERAL" ./results/sourcehunt/sh-*/report.md
```

### 8. Findings Pool + Cross-Run Dedup

```bash
# Run sourcehunt twice on same repo:
clearwing sourcehunt https://github.com/DaveGamble/cJSON --depth standard
clearwing sourcehunt https://github.com/DaveGamble/cJSON --depth standard

# Verify:
# - findings_pool.jsonl exists in session dir
# - Second run shows "dedup" or reduced finding count in logs
# - Historical DB populated
ls ~/.clearwing/historical_findings.db 2>/dev/null || echo "check results dir"
```

### 9. Band Promotion

```bash
clearwing sourcehunt https://github.com/DaveGamble/cJSON \
    --depth deep --starting-band fast --max-band deep

# Verify in logs:
# - "Promoting <file> from fast to standard band" messages
# - spent_per_band shows distribution across fast/standard/deep
# - Report includes band_stats with promotion counts
grep -i "promot" ./results/sourcehunt/sh-*/report.md
```

### 10. Entry-Point Sharding

```bash
# Works automatically at depth=deep for high-rank files with >50K LoC project:
clearwing sourcehunt https://github.com/FFmpeg/FFmpeg \
    --depth deep --shard-entry-points --budget 20

# Verify:
# - Logs show "Entry-point extraction" with count
# - Work items include function-level shards (path:function_name)
# - Report shows subsystem + entry-point coverage
```

### 11. Subsystem Hunting

```bash
clearwing sourcehunt https://github.com/FFmpeg/FFmpeg \
    --depth standard --enable-subsystem-hunt \
    --subsystem-paths libavcodec/h264

# Verify:
# - Logs show "Subsystem hunt: N targets identified"
# - Subsystem-level findings appear in report
# - subsystems_hunted > 0 in result
```

### 12–16. Exploit / Elaboration / Stability / Variant / Auto-Patch

```bash
# All integrated into the standard pipeline — exercise via:
clearwing sourcehunt https://github.com/DaveGamble/cJSON \
    --depth deep \
    --enable-elaboration \
    --enable-auto-patch

# Verify for each:
# [12] Exploit: logs show "Agentic exploiter" attempts
# [13] Elaboration: logs show "Elaboration" for exploited findings
# [14] Stability: logs show "Stability check" with success rate %
# [15] Variant: logs show "Variant loop: N patterns, M matches"
# [16] Auto-patch: logs show "Auto-patcher" attempts, patches in output
```

### 17–20. Behavioral Monitor / Artifact Store / Commitments / Calibration

```bash
# These are automatically active (or opt-in):
clearwing sourcehunt https://github.com/DaveGamble/cJSON \
    --depth standard --enable-artifact-store

# Verify:
# [17] Behavior: logs show "Behavior monitor" alerts if any
# [18] Artifact: encrypted exploit stored (check artifact store dir)
# [19] Commitments: auto-committed findings at root_cause_explained level
# [20] Calibration: severity tracking data persisted
```

### 21. Streaming Support

```bash
clearwing interactive --target 127.0.0.1

# Verify:
# - Agent responses stream token-by-token (not all-at-once)
# - Think tags are filtered from display
# - Legacy mode (--no-tui) also streams

clearwing interactive --no-tui --target 127.0.0.1
# Type "scan ports" and verify live text output
```

### 22–25. Infrastructure (Protocols, Sandbox, Provider, Config)

```bash
# Agent protocols: verified by type checker
uv run python -m mypy clearwing/agent/runtime.py --no-error-summary 2>&1 | head -5

# Sandbox hardening: inspect container config
clearwing sourcehunt https://github.com/DaveGamble/cJSON --depth standard
# Verify in Docker: seccomp profile applied, capabilities dropped

# Provider catalog:
clearwing config --list-providers

# Config home:
python -c "from clearwing.core.config import clearwing_home; print(clearwing_home())"
# Should print ~/.clearwing or $CLEARWING_HOME
```

### 26–30. Bug Fixes

```bash
# [26] Port scanner — unprivileged scan works:
clearwing scan 127.0.0.1 -p 22,80,443
# Verify: returns results without needing sudo

# [27] NVD timeout — no traceback spam:
clearwing scan 127.0.0.1 --detect-services 2>&1 | grep -c "Traceback"
# Should be 0

# [28] aiohttp session — no "Unclosed client session" warning:
clearwing scan 127.0.0.1 --detect-services 2>&1 | grep -i "unclosed"
# Should be empty

# [29] Version formatting:
clearwing scan <host-with-http> --detect-services
# Verify: shows "HTTP v2.4.41" or "HTTP (nginx)" — never "vNone"

# [30] Doctor macOS:
clearwing doctor
# Verify: no spurious "strace not on PATH" warning on macOS
```

---

## Quick Smoke Test (all features in ~5 minutes)

```bash
# 1. Doctor check
clearwing doctor

# 2. Port scan (bug fix #26)
clearwing scan 127.0.0.1 -p 80

# 3. Quick sourcehunt (exercises validator, findings pool, variant loop)
clearwing sourcehunt https://github.com/DaveGamble/cJSON --depth quick

# 4. Disclosure queue (exercises disclosure DB)
clearwing disclose status

# 5. Interactive streaming
echo "quit" | clearwing interactive --no-tui

# 6. Config home
python -c "from clearwing.core.config import clearwing_home; print(clearwing_home())"
```
