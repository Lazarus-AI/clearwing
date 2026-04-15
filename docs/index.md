# Clearwing

**Autonomous vulnerability scanner and source-code hunter built on
LangGraph.**

Clearwing is a dual-mode offensive-security tool:

- **Network-pentest agent** — a ReAct-loop agent that scans live
  targets, enumerates services, detects vulnerabilities, attempts
  exploits, and writes reports. Runs on top of a Docker-sandboxed
  Kali toolbox when one is configured. 63 tools, gated through a
  guardrail/approval layer so destructive operations pause for a
  human.
- **Source-code hunter** (Overwing) — a file-parallel agent-driven
  discovery pipeline that ranks source files by attack surface, fans
  out per-file hunter agents, uses ASan/UBSan crashes as ground
  truth, verifies findings with an adversarial second-pass agent,
  optionally generates exploits and validated patches, and emits
  SARIF/markdown/JSON reports with explicit evidence levels
  (`suspicion → static_corroboration → crash_reproduced →
  root_cause_explained → exploit_demonstrated → patch_validated`).

## What's here

| Page | What you'll learn |
|---|---|
| [**Quickstart**](quickstart.md) | Install, run a network scan, run a sourcehunt pass, read the results |
| [**Architecture**](architecture.md) | How the ReAct loops, sandboxes, capabilities layer, Finding dataclass, and knowledge graph fit together |
| [**CLI reference**](cli.md) | Every `clearwing <subcommand>` flag, with examples |
| [**API reference**](api.md) | `clearwing.findings.Finding`, `clearwing.agent.graph.build_react_graph`, the sourcehunt runner, auto-generated from docstrings |
| [**Source-code hunter deep dive**](openglass.md) | The original integration design for Overwing — ranker, hunter specialists, evidence ladder, mechanism memory, variant loops |

## Project status

Pre-1.0.0 release hygiene is underway. The release plan tracks
through six phases; all of phases 0–4 plus most of phase 5 have
shipped under the current commit history. The remaining Phase 5
items (`.reference/` history purge, README trim) are awaiting
operator approval for history-rewriting actions. Phase 6 (tag
`v1.0.0`, publish GitHub Release) is the next milestone.

See `CHANGELOG.md` at the repo root for the running change list.

## Not for

- Running scans against targets you don't own or aren't authorized
  to test. Clearwing is an offensive tool and provides no technical
  barrier to misuse — authorization is entirely the operator's
  responsibility.
- Replacing your security team. Clearwing surfaces candidate
  findings; triage and fix decisions stay with humans.

## Reporting

- Vulnerabilities **in** Clearwing → `SECURITY.md` (GitHub Security
  Advisories).
- Vulnerabilities Clearwing **finds in other software** → that
  vendor's disclosure channel. `clearwing sourcehunt --export-disclosures`
  generates MITRE and HackerOne templates as a starting point.
