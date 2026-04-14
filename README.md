# Clearwing

A comprehensive, modular vulnerability scanner and exploiter with an AI-powered interactive agent. Designed for authorized security testing and vulnerability assessments.

## Features

- **Port Scanning**: SYN and Connect scans with configurable threading
- **Service Detection**: Banner grabbing and version fingerprinting
- **OS Detection**: TTL-based and active TCP fingerprinting
- **Vulnerability Scanning**: Local CVE database + NVD API integration
- **Exploitation**: RCE, privilege escalation, and password cracking modules
- **Metasploit Integration**: Bridge to Metasploit RPC API
- **Reporting**: Text, JSON, HTML, and Markdown report formats
- **Database**: SQLite storage for scan history and results
- **Interactive AI Agent**: LangGraph-powered ReAct loop with Claude for autonomous pentest workflows
- **Kali Docker Integration**: Spin up Kali Linux containers for specialized security tools
- **Runtime Tool Creation**: Create custom tools on the fly during interactive sessions

## Advanced / Military-Grade Capabilities

- **Tactical Edge Autonomy**: Support for local, open-weights LLM execution (Llama-3, Mistral) for air-gapped or disconnected environments.
- **Advanced OPSEC**: Polymorphic payload obfuscation (XOR/Base64) to evade static EDR signatures.
- **Cryptographic Deconfliction**: HMAC-SHA256 watermarking of all payloads to prevent "cyber fratricide" and allow friendly force identification.
- **Asynchronous C2 Mesh**: Generation of resilient sleeper beacons with randomized jitter for stealthy persistence.
- **Kinetic/OT Operations**: Specialized scanning for Industrial Control Systems (ICS) including Modbus, Siemens S7, and DNP3.
- **Interactive Attack Graph**: Live, interactive D3.js visualization of the attack surface and lateral movement paths.

## Source-Code Vulnerability Hunting (Overwing)

Overwing is the white-box companion to the network scanners. It runs a file-parallel agent-driven discovery pipeline against a cloned repository. Every verified finding carries an `evidence_level` on a six-step ladder that gates downstream budget allocation:

`suspicion → static_corroboration → crash_reproduced → root_cause_explained → exploit_demonstrated → patch_validated`

The Exploiter only runs on findings `>= crash_reproduced`. The Auto-Patcher only runs on findings `>= root_cause_explained`. Findings that reach `patch_validated` are the gold standard.

### The pipeline

```
preprocess → rank → [harness generator → crash seeds] → tiered hunt
    → adversarial verify → patch oracle → extract mechanisms → variant loop
    → exploit triage → auto-patch → report
```

1. **Preprocess** — clone, enumerate, statically pre-scan with SourceAnalyzer's regex/AST patterns, tag files (`parser`, `memory_unsafe`, `crypto`, `auth_boundary`, `fuzzable`, `syscall_entry`), build a tree-sitter callgraph, propagate attacker-reachability from entry-tagged files, run a Semgrep sidecar for hint injection, **and run an intra-procedural taint analyzer** that traces source→sink paths (e.g. `read(fd, buf, n)` → `memcpy(dst, buf, n)`, `request.args.get()` → `cursor.execute()`) with 18 C sources / 14 C sinks / 14 Python sources / 11 Python sinks. Files with confirmed taint paths get a surface-4 floor in the ranker.
2. **Three-axis rank** — score each file on `surface * 0.5 + influence * 0.2 + reachability * 0.3`. The influence axis catches "boring" files whose definitions propagate across many callers (the `constants.h` with `MAX_BUF=400` used in 50 `memcpy` calls case that a single-axis ranker would drop). Files tagged `parser` / `fuzzable` with `surface>=4` get a `+0.5` rank boost because the harness generator seeds their hunters with crash evidence.
3. **Crash-first harness generator** *(depth=deep)* — for every rank-4+ parser/fuzzable C/C++ file, the LLM writes a libFuzzer harness, compiles it in the sandbox with ASan, runs it for a per-harness time budget, and captures any crashes. Hunters for fuzzed files get the easier "explain this crash" framing instead of cold-reading.
4. **Tiered hunt** — files split into Tier A/B/C by priority. Budget allocated 70/25/5 with rollover. Tier C files get a different prompt focused on propagation risk (buffer adequacy, sentinel collisions, type truncation, unsafe defaults). Hunters dispatch to one of **six specialists** by tag + language:
   - `kernel_syscall` — `copy_from_user` bounds, ioctl capability gating, refcount asymmetry, TOCTOU (files tagged `syscall_entry`)
   - `crypto_primitive` — timing side channels, nonce reuse, key lifecycle, MAC-then-decrypt, PRNG sources (C/C++/Rust `crypto` files)
   - `web_framework` — SQL injection, SSRF, IDOR, CSRF, mass assignment, deserialization (Python/JS/Ruby/PHP files in `views`/`routes`/`handlers`/`controllers`/`api` dirs)
   - `memory_safety` — length vs allocation, width truncation, UAF, sentinel collisions (C/C++ parsers / memory_unsafe)
   - `logic_auth` — boolean defaults, comparison semantics, fail-open, cache invalidation (`auth_boundary` and protocol-level crypto)
   - `general` — fallback
5. **Adversarial verify** — a second-pass agent with independent context (never sees the hunter's reasoning) is required to steel-man BOTH sides: construct the strongest pro-vuln argument AND the strongest counter-argument, then find tie-breaker evidence. Prevents false positives and motivated dismissal. The adversarial-budget gate (default: only findings with `evidence_level >= static_corroboration`) cuts cost on suspicion-only findings.
6. **Patch oracle** — a truth test. Write a minimal defensive fix, recompile in the sandbox, re-run the PoC. Crash gone → root cause theory is causally validated (bumps to `root_cause_explained`). Crash survives → theory is suspect.
7. **Mechanism memory** — verified findings feed a cross-run JSONL store keyed on abstract mechanisms ("length field trusted before alloc; size_t wrapping"), not free-text descriptions. Recall uses pure-Python TF-IDF over the mechanism text by default, with an optional chromadb-backed vector search when `chromadb` is installed. Recalled mechanisms inject as hint context into hunter prompts on subsequent runs.
8. **Variant hunter loop** — for each verified finding, auto-generate a grep regex + semantic description, search the codebase for structural matches, surface each match as a `discovered_by: variant_loop` finding with `related_finding_id` set. **Runs until fixpoint** (up to 3 iterations) — each pass's new seeds feed the next pass's pattern generation, compounding finding density inside one run.
9. **Exploit triage** — only on findings with sanitizer crash evidence. Successful PoC bumps severity to critical.
10. **Auto-patch** *(opt-in)* — on verified critical/high with root-cause explanation, write a minimal fix, recompile, re-run the PoC. Only validated patches (PoC stops crashing after apply) are included in the report. Optional `--auto-pr` opens draft PRs via the `gh` CLI.
11. **Report** — SARIF + markdown + JSON, findings sorted by evidence level descending. Optional `--export-disclosures` produces pre-filled MITRE CVE-request and HackerOne templates for every verified finding with `evidence_level >= root_cause_explained`.

### CLI

```bash
# Quick static-only sweep — preprocessor + ranker, no LLM hunters (free)
python clearwing.py sourcehunt /path/to/repo --depth quick

# Standard — sandboxed hunters, verifier (adversarial), patch oracle, mechanism
# memory, variant loop, exploit triage, taint analysis. Default 70/25/5 split.
python clearwing.py sourcehunt https://github.com/example/repo \
    --depth standard --budget 5

# Deep — adds the crash-first harness generator and enables auto-patch.
python clearwing.py sourcehunt /path/to/repo \
    --depth deep --budget 10 --max-parallel 8 \
    --auto-patch

# Override the budget split (e.g. more propagation audits)
python clearwing.py sourcehunt /path/to/repo --tier-split 60/30/10

# Skip Tier C propagation audits and roll that budget into Tier A
python clearwing.py sourcehunt /path/to/repo --skip-tier-c

# Disable specific features
python clearwing.py sourcehunt /path/to/repo \
    --no-variant-loop \
    --no-mechanism-memory \
    --no-patch-oracle

# Adversarial-budget gate — only spend steel-man prompt budget on findings
# whose evidence level is at least the threshold (default: static_corroboration).
# "always" disables the gate; "crash_reproduced" is the strictest useful setting.
python clearwing.py sourcehunt /path/to/repo \
    --adversarial-threshold crash_reproduced

# Export MITRE + HackerOne disclosure templates for every verified finding
# reaching evidence_level >= root_cause_explained. Templates are written to
# {output_dir}/{session_id}/disclosures/{mitre,hackerone}/*.md for human review.
python clearwing.py sourcehunt /path/to/repo \
    --depth standard --budget 5 \
    --export-disclosures \
    --reporter-name "Alice" \
    --reporter-affiliation "Acme Security" \
    --reporter-email alice@acme.com

# Watch mode — poll git for new commits and re-scan the blast radius
python clearwing.py sourcehunt /path/to/repo \
    --watch --poll-interval 300

# Watch mode + GitHub Checks API — post findings as check runs on each commit
# via the `gh` CLI (requires `gh auth login` and repo write permissions).
python clearwing.py sourcehunt /path/to/repo \
    --watch --github-checks \
    --github-check-name "Overwing Sourcehunt"

# Webhook mode — start an HTTP server that runs sourcehunt on each GitHub push
# event. Complements --watch (no polling latency). Requires HMAC shared secret.
python clearwing.py sourcehunt /path/to/repo \
    --webhook --webhook-port 8787 \
    --webhook-secret "$(cat ~/.webhook.secret)" \
    --webhook-allowed-repo acme/critical-service \
    --webhook-allowed-branch main \
    --github-checks

# CVE retro-hunt — LLM generates a Semgrep rule from a patch diff,
# then finds variants of the CVE pattern in the target repo.
python clearwing.py sourcehunt /path/to/repo \
    --retro-hunt CVE-2024-12345 \
    --patch-source /path/to/fix.patch

# Auto-patch mode with draft PRs
python clearwing.py sourcehunt /path/to/repo \
    --depth deep --budget 10 \
    --auto-patch --auto-pr
```

The interactive agent can also call the pipeline as a tool when it has access to a target's source code:

```
You: scan target 10.0.0.5 — and check the source code at https://github.com/example/webapp
Agent: [scans network] [calls hunt_source_code] Found 3 critical findings in src/auth.py
```

**Sandbox requirement**: `--depth standard` and `--depth deep` build per-hunt Docker containers (no network, read-only source mount, ASan/UBSan instrumented) so hunters can compile and run with sanitizers. The patch oracle and auto-patcher also require a sandbox to validate fixes by recompile + PoC replay — the verify-by-recompile gate is mandatory for auto-patches. `--depth quick` runs without Docker but skips all LLM-driven hunters.

**Sanitizer variants**: ASan/UBSan run in the primary sandbox image. Because MSan (MemorySanitizer) cannot coexist with ASan in the same binary, the hunter sandbox can build a **separate MSan variant image** on demand. Hunters call `compile_file(sanitizer_variant="msan")` / `run_with_sanitizer(sanitizer_variant="msan")` to target the MSan image — useful for uninitialized-memory bugs ASan can't detect. The variant images share the same read-only source mount and writable `/scratch` tmpfs; the sandbox manager caches both per hunter to avoid repeated container spawning.

### Mechanism memory location

Cross-run mechanisms are stored at `~/.clearwing/sourcehunt/mechanisms.jsonl` (or the path in `$CLEARWING_HOME`). Each line is one mechanism. Delete the file to reset the store.

**Recall backends**:
- **TF-IDF** *(default)* — pure-Python TF-IDF over `{summary + tags + keywords + what_made_it_exploitable + cwe}` with cosine similarity. No external dependency. Production-tuned stopword list preserves security terms like `memcpy`, `length`, `copy_from_user`.
- **chromadb** *(optional)* — install `chromadb` and the store automatically upgrades to sentence-transformers embeddings via an ephemeral chromadb client. The JSONL file remains the authoritative persistence format — chromadb is rebuilt from it at load time.
- **keyword** *(legacy)* — language + tag overlap only. Available via `MechanismStore(backend="keyword")` if you want deterministic recall for tests.

### Reproducing Glasswing's OpenBSD and FFmpeg outcomes

Anthropic's Project Glasswing reported N-day and N+1 rediscoveries across major C/C++ codebases, FFmpeg and OpenBSD among them. Overwing is an open implementation of the same file-parallel methodology, so you can point it at the same targets and see what rediscovers. **Overwing is not Glasswing's model** — Opus-4.6 is plausibly weaker than whatever Anthropic ran internally, so don't expect a 1:1 hit rate. Treat these as calibration runs: they demonstrate the pipeline works end-to-end on real codebases and let you compare what the open-source pipeline recovers to what Anthropic disclosed.

Both runs require a working Docker daemon (for the sandbox), an `ANTHROPIC_API_KEY`, and a willingness to spend real budget. A five-dollar run is useful; a fifty-dollar run is meaningfully better. Budget linearly with file count — OpenBSD's `sys/netinet` alone is ~150 files, FFmpeg's `libavcodec` is ~900.

#### 1. FFmpeg — a parser-heavy codec (`libavcodec/`)

FFmpeg is the standard benchmark: dozens of codec parsers, decades of memory-safety bug history, and a well-maintained OSS-Fuzz corpus. Glasswing's own example config in [docs/openglass.md](docs/openglass.md) pointed at FFmpeg.

```bash
# 1. Clone FFmpeg
git clone --depth 1 https://github.com/FFmpeg/FFmpeg.git /tmp/ffmpeg

# 2. Scope to libavcodec first — it's where the crashes live
python clearwing.py sourcehunt /tmp/ffmpeg/libavcodec \
    --local-path /tmp/ffmpeg/libavcodec \
    --depth deep \
    --budget 20 \
    --max-parallel 8 \
    --tier-split 75/20/5 \
    --output-dir ./results/ffmpeg-libavcodec

# 3. If you have a specific CVE patch you want to retro-hunt for variants:
python clearwing.py sourcehunt /tmp/ffmpeg \
    --local-path /tmp/ffmpeg \
    --retro-hunt CVE-2020-27814 \
    --patch-source <git-sha-of-the-fix-commit> \
    --patch-repo /tmp/ffmpeg
```

What to look for in `./results/ffmpeg-libavcodec/`:

- **`findings.sarif`** — open in your IDE or at [sarif-viewer.azurewebsites.net](https://sarif-viewer.azurewebsites.net/). Findings are sorted by `evidence_level` descending — the ones tagged `patch_validated` are the gold standard.
- **`report.md`** — human-readable summary. Look for `propagation_buffer_size` / `propagation_sentinel` findings in `libavcodec/*.h` header files. Those are the FFmpeg-style "boring file, huge influence" bugs the influence axis was designed to catch.
- **`manifest.json`** — cost breakdown by tier. If the Tier C propagation auditors are finding anything meaningful, it'll show up here.

#### 2. OpenBSD — kernel networking (`sys/netinet/`)

OpenBSD's network stack is small enough to fit in a single run and has a well-known exploit history. The `sys/netinet/` directory is a good first target.

```bash
# 1. Clone OpenBSD-src — the mirror is faster than cvsweb
git clone --depth 1 https://github.com/openbsd/src /tmp/openbsd
cd /tmp/openbsd/sys/netinet
ls *.c | wc -l     # ~150 files

# 2. Run sourcehunt scoped to sys/netinet
python clearwing.py sourcehunt /tmp/openbsd/sys/netinet \
    --local-path /tmp/openbsd/sys/netinet \
    --depth deep \
    --budget 30 \
    --max-parallel 6 \
    --tier-split 70/25/5 \
    --output-dir ./results/openbsd-netinet
```

Points worth checking:

- **Callgraph reachability** — the callgraph builder should identify `ip_input.c`, `tcp_input.c`, `udp_input.c`, and the various `*_usrreq.c` files as entry points (they handle packet ingress). Files called from those entry points should get high `reachability` scores.
- **Specialist routing** — anything with `crypto_` prefix routes to the `logic_auth` specialist; the bulk of networking code goes to `memory_safety`. You can see the split in the per-finding `discovered_by` field.
- **Propagation findings** — OpenBSD defines many packet-length constants in headers (`IP_MAXPACKET`, `TCP_MAXWIN`, etc.). If Tier C flags any of these as propagation risks, that's the influence axis doing its job.

#### 3. Compare to Glasswing's disclosures

Anthropic's Glasswing blog post lists the specific CVEs and commits they rediscovered. After an Overwing run completes:

1. Filter the findings for the Glasswing-reported files. Compare file + finding type against Anthropic's disclosure.
2. For every CVE Glasswing caught that Overwing missed, try the retro-hunt mode with that specific patch to verify the pipeline *could* have found it given the right prompt or pattern.
3. Contribute surprises — bugs Overwing surfaced that aren't on Glasswing's list — back upstream via responsible disclosure (see the project's SECURITY.md).

#### Why your run will look different

- **Model tier**: The default routing uses Opus as the hunter and Sonnet as the verifier. A run with Haiku in the hunter slot will produce dramatically noisier output. A run with all-Opus costs more but recovers more.
- **Fuzz runtime**: Harness generation + libFuzzer in `--depth deep` is time-budgeted to 2 hours total across all harnesses by default. Bumping `HarnessGeneratorConfig.total_time_budget_seconds` in a custom runner (via the Python API) unlocks the long-tail crashes that 2 hours can't find.
- **Tier C catches different bugs**: The propagation auditor prompt is tuned for header-file / constants-file bugs. It won't find a conventional memcpy overflow — that's what Tier A is for. Run both tiers and compare.
- **Variant loop is single-pass**: A verified finding spawns pattern searches *once*. Re-running with `--no-variant-loop` disabled (or raising `VariantLoopConfig.max_iterations` via the Python API) lets the loop compound further within one run.

If you reproduce an interesting outcome, please open an issue with the run parameters, session ID, and a SARIF snippet. Comparison data is the most valuable input to this project.

## Installation

```bash
# Clone the repository
git clone https://github.com/Lazarus-AI/clearwing.git
cd clearwing

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # or: source venv/bin/activate.fish

# Install the package (and dev extras)
pip install -e '.[dev]'
```

### Requirements

- Python 3.10+
- Docker (optional, for Kali container features)
- `ANTHROPIC_API_KEY` environment variable (for interactive agent)

## Quick Start

```bash
# Basic scan
python clearwing.py scan 192.168.1.1

# Scan specific ports
python clearwing.py scan 192.168.1.1 -p 22,80,443

# Scan with exploitation
python clearwing.py scan 192.168.1.1 -e

# Generate HTML report
python clearwing.py scan 192.168.1.1 -o report.html -f html

# Start interactive AI agent
python clearwing.py interactive --target 192.168.1.1

# View scan history
python clearwing.py history
```

## Commands

### `scan` -- Run a scan

```
python clearwing.py scan <target> [options]

Options:
  -p, --ports PORTS       Ports to scan (e.g., 22,80,443 or 1-1024)
  -t, --threads THREADS   Number of concurrent threads (default: 100)
  -s, --stealth           Stealth mode
  -e, --exploit           Attempt exploitation
  -o, --output FILE       Output file for report
  -f, --format FORMAT     Report format: text, json, html, markdown
  -v, --verbose           Verbose output
```

### `interactive` -- AI agent session

```
python clearwing.py interactive [options]

Options:
  --model MODEL   LLM model name (default: claude-sonnet-4-6)
  --target TARGET Initial target IP address
```

The interactive agent provides a conversational interface where you can direct pentest activities in natural language. The agent follows a ReAct (Reason + Act) loop:

1. You describe what you want to do
2. The agent reasons about which tools to use
3. Tools execute (exploits require your approval)
4. Results feed back into the conversation

**Example session:**

```
You: scan 10.0.0.5 for open ports
Agent: [calls scan_ports] Found 3 open ports: 22/tcp (SSH), 80/tcp (HTTP), 443/tcp (HTTPS)

You: detect what services are running
Agent: [calls detect_services] SSH: OpenSSH 8.2, HTTP: Apache 2.4.41, HTTPS: Apache 2.4.41

You: check for vulnerabilities
Agent: [calls scan_vulnerabilities] Found 2 vulnerabilities: CVE-2017-9788 (CVSS 7.5), ...

You: set up a kali container and run nmap
Agent: [calls kali_setup] Started Kali container abc123
APPROVAL REQUIRED: Approve running in Kali container: nmap -sV 10.0.0.5 [y/n]
```

Type `quit` or `exit` to end the session. Active Kali containers are cleaned up automatically.

### `report` -- Generate report from database

```
python clearwing.py report <target> [-o FILE] [-f FORMAT]
```

### `history` -- View scan history

```
python clearwing.py history [target]
```

### `config` -- Show or edit configuration

```
python clearwing.py config [--set KEY VALUE] [--save FILE]
```

## Architecture

```
clearwing/
├── core/                    # Core engine and utilities
│   ├── engine.py            # Linear workflow orchestrator
│   ├── config.py            # YAML configuration management
│   ├── module_loader.py     # Dynamic module loading
│   └── logger.py            # Logging setup
├── scanners/                # Scanning modules
│   ├── port_scanner.py      # SYN/Connect port scanning
│   ├── service_scanner.py   # Banner grabbing, version detection
│   ├── vulnerability_scanner.py  # CVE lookup (local DB + NVD API)
│   └── os_scanner.py        # OS fingerprinting via TTL/TCP
├── exploiters/              # Exploitation modules
│   ├── rce_exploits.py      # Remote code execution exploits
│   ├── privilege_escalation.py  # Linux/Windows privesc checks
│   ├── password_crackers.py # SSH, FTP, SMB, HTTP brute force
│   └── metasploit_bridge.py # Metasploit RPC API bridge
├── agent/                   # AI agent (LangGraph)
│   ├── state.py             # Agent state schema (TypedDict)
│   ├── graph.py             # ReAct loop graph construction
│   ├── prompts.py           # System prompt with dynamic context
│   ├── tools/               # @tool wrappers for all modules
│   │   ├── scanner_tools.py
│   │   ├── exploit_tools.py
│   │   ├── kali_docker_tool.py
│   │   ├── reporting_tools.py
│   │   ├── utility_tools.py
│   │   └── dynamic_tool_creator.py
│   └── custom_tools/        # Runtime-created tools land here
├── reporting/
│   └── report_generator.py  # Text, JSON, HTML, Markdown reports
├── database/
│   └── models.py            # SQLite schema and queries
├── ui/
│   └── cli.py               # Argparse CLI with all commands
└── utils/
    └── helpers.py            # IP validation, CVSS severity, etc.
```

## Agent Tools

The interactive agent has access to 22 built-in tools:

| Category | Tools | Approval Required |
|----------|-------|-------------------|
| **Scanning** | `scan_ports`, `detect_services`, `scan_vulnerabilities`, `detect_os` | No |
| **Exploitation** | `exploit_vulnerability`, `enumerate_privesc`, `crack_password` | Yes |
| **Metasploit** | `metasploit_exploit`, `metasploit_run_command`, `metasploit_list_sessions` | Yes (except list) |
| **Kali Docker** | `kali_setup`, `kali_execute`, `kali_install_tool`, `kali_cleanup` | Yes (execute only) |
| **Reporting** | `generate_report`, `save_report`, `query_scan_history`, `search_cves` | No |
| **Utility** | `validate_target`, `calculate_severity` | No |
| **Meta** | `create_custom_tool`, `list_custom_tools` | No |

Tools marked with "Approval Required" will pause execution and prompt you for confirmation before proceeding.

### Dynamic Tool Creation

The agent can create new tools at runtime. For example, you can ask:

> "Create a tool that checks if a URL returns a 200 status code"

The agent will generate a `@tool`-decorated Python function, save it to `clearwing/agent/custom_tools/`, and recompile the graph so the new tool is immediately available in the same session.

## API Usage

### Linear Workflow (CoreEngine)

```python
import asyncio
from clearwing.core import CoreEngine, Config, ScanConfig

config = Config()
engine = CoreEngine(config)

scan_config = ScanConfig(
    target='192.168.1.1',
    ports=[22, 80, 443],
    exploit=False
)

result = asyncio.run(engine.scan('192.168.1.1', scan_config))
print(engine.get_report('text'))
```

### Agent (Programmatic)

```python
from clearwing.agent import create_agent, AgentState
from langchain_core.messages import HumanMessage

graph = create_agent(model_name="claude-sonnet-4-6")
config = {"configurable": {"thread_id": "my-session"}}

result = graph.invoke(
    {
        "messages": [HumanMessage(content="Scan 192.168.1.1 for open ports")],
        "target": "192.168.1.1",
        "open_ports": [],
        "services": [],
        "vulnerabilities": [],
        "exploit_results": [],
        "os_info": None,
        "kali_container_id": None,
        "custom_tool_names": [],
    },
    config,
)
```

## Configuration

Default configuration can be customized via YAML file or the `config` command:

```yaml
scanning:
  scan_timeout: 1
  max_threads: 100
exploitation:
  auto_exploit: false
  metasploit_host: 127.0.0.1
  metasploit_port: 55553
  metasploit_password: msf
reporting:
  default_format: text
database:
  path: clearwing.db
```

## Testing

```bash
# Unit tests (no network or Docker required)
pytest tests/test_agent.py tests/test_dynamic_tools.py -v

# Docker integration tests (requires Docker daemon)
pytest tests/test_kali_docker.py -v

# All tests
pytest tests/ -v
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing, educational purposes, and CTF competitions only. Always ensure you have explicit permission before scanning or exploiting target systems. Unauthorized access to computer systems is illegal.
