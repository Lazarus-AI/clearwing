# Security Policy

Clearwing is an offensive-security tool. That creates two distinct
reporting lanes that are easy to conflate — please read the scope
below before filing.

## Scope

**In scope — vulnerabilities in clearwing itself.** For example:
- Sandbox escapes from the hunter's Docker container into the host.
- Auth bypasses in the web UI (`clearwing webui`) or the MCP server.
- Command injection via tool arguments that escape the subprocess
  quoting Clearwing applies before dispatching.
- Credential leakage in logs, reports, the knowledge graph, or the
  mechanism store.
- Disclosure-template injection via finding fields that get written
  unescaped into MITRE/HackerOne templates.
- `pickle` / `eval` / untrusted-deserialization reachable from any
  non-local input (webhook server, MCP stdio, REST endpoints).
- Supply-chain issues in the distributed wheel or sdist (missing
  `py.typed`, stray absolute paths, bundled secrets, etc.).

**Out of scope — vulnerabilities that Clearwing *finds*.** When a
sourcehunt run or a network scan surfaces a bug in someone else's
software, that is not a vulnerability in Clearwing — it's expected
output. Please report those to the affected vendor through their
own disclosure channel. Clearwing's
`--export-disclosures` flag produces MITRE CVE-request and HackerOne
templates specifically to help with this hand-off.

Out-of-scope findings we will close without action:
- Reports that Clearwing "allowed" a scan against a target — this is
  the tool's purpose; authorization is the operator's responsibility.
- Reports that sandbox images include known-vulnerable compilers or
  libraries — the sandboxes are disposable, unreachable from the
  network, and never hold production data.
- Reports that an LLM provider Clearwing talks to (Anthropic, OpenAI,
  local models) is insecure — that is the provider's responsibility.
- Issues in third-party Python packages Clearwing depends on —
  please file upstream and ping us here only if Clearwing needs a
  pin bump to propagate the fix.

## How to report

Use **GitHub Security Advisories** — the private disclosure channel
built into the repo:

1. Go to <https://github.com/Lazarus-AI/clearwing/security/advisories/new>
2. Fill in the report. Include:
   - A short, specific title.
   - Affected version(s) (git SHA or release tag — `clearwing --version`).
   - Reproduction steps. Sandboxed PoCs are welcome and encouraged.
   - Impact assessment. What does exploitation give the attacker?
   - Your preferred credit line.

Do **not** open a public GitHub issue for anything with security
impact. If you don't have a GitHub account, email the maintainer at
<eric@quixi.ai> with subject `clearwing security:` — encryption is
optional but if you want it, say so in the first message and we'll
arrange a key exchange.

## What to expect

- **Acknowledgment** within 3 business days.
- **Triage decision** (confirmed / duplicate / out-of-scope / needs
  more info) within 7 business days.
- **Fix target**: critical issues within 14 days, high within 30,
  everything else on a best-effort basis. A fixed release, a CVE
  request if warranted, and credit in `CHANGELOG.md` come with
  the fix.
- Embargoed disclosure is fine — tell us the date you want to go
  public and we'll coordinate.

## Safe harbor

Security research on Clearwing that follows this policy is
authorized. We won't pursue legal action against researchers who:

- Report privately via the channels above before going public.
- Stop at proof-of-concept and don't pivot into production
  infrastructure, user data, or third-party systems.
- Don't use the finding to access, modify, or destroy data you
  don't own.
- Give us a reasonable window to fix before public disclosure.

This is not a bug-bounty program — Clearwing is MIT-licensed
open source and there is no monetary reward. We do give credit in
the CHANGELOG and the release notes, and we're happy to provide
a public statement of appreciation you can link from a CV.
