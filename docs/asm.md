# Attack Surface Management

Clearwing is deep on a target you already have. **ASM** adds the front half of an
engagement: discovering what's out there, tracking what changes, and feeding new
assets into Clearwing's existing scanning and verification.

It is passive-first and host-safe — discovery queries public archives (crt.sh,
the Wayback Machine, CISA KEV, EPSS) the same way the CVE/NVD lookups already do,
plus light DNS resolution and HTTP liveness probing. **ASM never exploits and
never triggers approval-gated actions automatically** — it discovers and scans,
then hands findings to the normal pipeline.

## Quick start

```bash
# One-shot discovery of a domain's surface (passive recon), writes a report
clearwing asm scan example.com

# Discover + probe live web hosts + a screenshot gallery for triage
clearwing asm scan example.com --mode web-assessment --screenshot

# Full discovery, then port/service/vuln-scan every host (threat-intel ranked)
clearwing asm scan example.com --mode external-sweep

# List what you know, and drill into a scope
clearwing asm list
clearwing asm list example_com
```

Everything is keyed by a **scope** — a named engagement. A bare domain becomes an
ad-hoc scope (`example.com` → `example_com`); named scopes live in config:

```yaml
# ~/.clearwing/config.yaml
asm:
  scopes:
    acme:
      domains: [acme.com, acme.io]
      exclusions: [legacy.acme.com]
```

Then `clearwing asm scan acme` operates on the whole engagement.

## Continuous monitoring

```bash
clearwing asm monitor acme                 # daemon: re-discover on an interval
clearwing asm monitor acme --once          # a single cycle (for cron / the scheduler)
clearwing asm monitor acme --interval 3600 # hourly
```

Each cycle re-runs discovery, records only the **new** assets (delta detection
against the SQLite asset store), emits an `ASSET_DISCOVERED` event for each, and —
by default — port/service/vuln-scans new hosts. There is no built-in scheduler;
run the daemon, or drive `--once` from cron or `clearwing schedule`.

## Notifications

Set a Slack incoming-webhook (or a generic webhook) and ASM posts on new assets
and new findings:

```yaml
asm:
  slack_webhook_url: "https://hooks.slack.com/services/..."   # or env CLEARWING_SLACK_WEBHOOK
```

`asm monitor` notifies automatically when a webhook is configured; add `--notify`
to `asm scan`.

## Threat-intel prioritization

Findings are enriched with **CISA KEV** (exploited in the wild) and **EPSS**
(exploitation probability) and sorted KEV-first, then by EPSS, then CVSS/severity
— so reports and sweeps lead with what's dangerous. Both feeds are public; the
KEV catalog is cached under `~/.clearwing/asm/`.

## Where things live

- Asset inventory: `~/.clearwing/asm/assets.db` (scope-keyed SQLite; `first_seen`
  / `last_seen` give the temporal delta).
- Reports: `results/asm/<scope>/asm-report.{md,json}`.
- Discovered assets are also projected into the knowledge graph, so
  `clearwing graph` and `query_knowledge_graph` see the surface (domain →
  subdomain → host → port → service).

## Agent tools

The discovery primitives are also agent tools, so an interactive/operator agent
can drive them directly: `discover_subdomains`, `lookup_cert_transparency`,
`discover_wayback_urls`, `resolve_hosts`, `probe_liveness`, `screenshot_surface`.

## Optional enrichment sources

Passive discovery works out of the box. These add coverage when their API keys
are in the environment: `GITHUB_API_KEY` (GitHub code-search subdomains),
`SHODAN_API_KEY`, `CENSYS_API_ID` / `CENSYS_API_SECRET`.
