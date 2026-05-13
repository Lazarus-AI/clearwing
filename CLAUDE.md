# Clearwing

Clearwing is an AI-driven security research and pentesting framework. It provides ~100 agent tools organized into categories below.

## Tool-first principle

Always reach for clearwing's built-in tools before using raw `urllib`/`requests`, Ghost OS, or ad-hoc scripts. The toolset handles logging, approval gates, history capture, and isolation automatically.

**Decision order when you need to interact with a target:**

1. **clearwing agent tools** — `proxy_request`, `browser_navigate`, `mitm_start`, `srp_handshake`, etc. These log to history, respect approval gates, and integrate with the knowledge graph.
2. **kali_setup + kali_execute** — for anything that needs OS-level isolation (running exploit code, headless browsers, traffic capture). Never run untrusted code or target interaction on the host OS directly.
3. **Raw Python/Bash** — only for local computation, file manipulation, or one-off parsing that no tool covers.
4. **Ghost OS / host browser** — last resort only. Prefer Playwright browser tools or Kali container.

## Tool categories

### Recon (`agent/tools/recon/`)
- **browser_tools** — Playwright browser automation: navigate, fill, click, execute JS, cookies, screenshots
- **proxy_tools** — HTTP request proxy with history capture, replay, and export
- **mitm_proxy** — Route-based MITM interception on browser tabs with request/response injection
- **auth_recorder** — Capture and replay authentication flows
- **session_tools** — Token extraction, mutation testing, session fixation detection
- **bundle_tools** — JS bundle fetching, secret pattern search, API route extraction
- **webcrypto_hooks** — Instrument browser WebCrypto API calls
- **cc_tools** — Confidential computing endpoint schema discovery and testing
- **pivot_tools** — SSH/Chisel network pivoting

### Crypto (`agent/tools/crypto/`)
- **srp_tools** — SRP-6a handshake, verifier extraction, offline cracking, timing analysis
- **kdf_tools** — KDF parameter analysis, cracking cost estimation
- **vault_tools** — JWE/vault blob parsing, encryption strength assessment
- **credential_tools** — 2SKD entropy analysis, secret key validation
- **timing_tools** — HTTP endpoint timing probes, binary search, character brute-force
- **recovery_tools** — 1Password recovery code generation and validation testing
- **mycelium_tools** — Device pairing channel creation, enumeration, peer validation

### Scan (`agent/tools/scan/`)
- **scanner_tools** — Port scanning, service detection, vulnerability scanning, OS fingerprinting
- **tls_tools** — Certificate inspection, cipher enumeration, downgrade testing

### Exploit (`agent/tools/exploit/`)
- **exploit_tools** — RCE, privesc, password cracking, Metasploit integration
- **exploit_search** — Exploit-DB search and download
- **payload_tools** — Payload obfuscation, watermarking, C2 beacon generation

### Ops (`agent/tools/ops/`)
- **kali_docker_tool** — Spin up isolated Kali container, run commands, install tools
- **mcp_tools** — Connect to external MCP servers
- **dynamic_tool_creator** — Create new tools at runtime
- **skill_tools** — Load Claude Code skills

### Data (`agent/tools/data/`)
- **analysis_tools** — Static source analysis, taint flow tracing (Python, JS, PHP, Java, Ruby, Go)
- **cve_tools** — NVD CVE search and detail lookup
- **knowledge_tools** — Knowledge graph queries
- **memory_tools** — Cross-session knowledge storage and recall

### Meta (`agent/tools/meta/`)
- **reporting_tools** — Report generation, scan history queries
- **remediation_tools** — Patch generation, remediation verification
- **sourcehunt_tools** — AI-powered vulnerability hunting pipeline
- **wargame_tools** — CTF-specific utilities
- **utility_tools** — Target validation, severity calculation
- **ot_tools** — OT/ICS infrastructure scanning

## Isolation policy

- **Target interaction** (HTTP requests, exploitation, browser automation against targets) should run through clearwing tools or inside a Kali container — not via raw host OS commands.
- **Local analysis** (parsing files, computing hashes, reading JS bundles) is fine on the host.
- **Ghost OS** is available but is a host-OS tool — use it only when clearwing's Playwright browser tools can't do the job.

## Running tests

```
python -m pytest tests/ -v
ruff check clearwing/
```

## Project structure

```
clearwing/
  agent/          # Agent runtime, tooling framework, tool registry
    tools/        # All agent tools (see categories above)
  crypto/         # Crypto primitives: SRP, 2SKD, stats
  sandbox/        # Docker sandbox execution
  exploitation/   # Exploiter classes, payload framework
  ...
```
