# Hexis + CRC integration fork

This branch (`with-crc-hexis-integration`) is the **Lazarus-private integration line** for ClearWing changes required by the Hexis stack (ClearWing sidecar, Hunter sandbox/Docker wiring, CRC-related runtime hooks).

- **Canonical remote:** `https://github.com/Lazarus-AI/clearwingpro.git` (private Lazarus fork — create on GitHub if missing)
- **Branch:** `with-crc-hexis-integration` (do **not** land Hexis-specific patches on upstream `Lazarus-AI/clearwing` `main` unless explicitly promoted)
- **Read-only sync reference:** `clearwing-main` → `https://github.com/Lazarus-AI/clearwing.git`

## Hexis parent repo

Hexis pins this tree as a git submodule at `workspace/runtime/clearwing-run/clearwing` (see parent `.gitmodules`).

## Push (operator credentials)

```bash
cd workspace/runtime/clearwing-run/clearwing
git checkout with-crc-hexis-integration
# One-time: create the private repo (if 404)
#   gh auth login
#   gh repo create Lazarus-AI/clearwingpro --private --description "ClearWing + Hexis/CRC integration fork"
git push -u origin with-crc-hexis-integration
```

Do **not** push integration commits to public/open-source ClearWing upstreams unless deliberately releasing.
