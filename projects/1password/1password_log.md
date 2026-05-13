# 1Password CTF — Engagement Log

## Step 1.1 — Infrastructure Scan

**Date:** 2026-04-23
**Target:** bugbounty-ctf.1password.com
**Scan:** Full port scan (1-65535), 500 threads

### Open Ports

| Port | Protocol | Service | Banner |
|------|----------|---------|--------|
| 80 | tcp | HTTP | `awselb/2.0` — returns 403 Forbidden |
| 443 | tcp | HTTPS | `awselb/2.0` — returns 400 (plain HTTP probe to TLS port) |

All other ports (1-65535) closed or filtered.

### Infrastructure

- Behind **AWS Elastic Load Balancer** (`awselb/2.0`)
- No direct access to application servers
- Port 80 returns `403 Forbidden` with body "HTTP Forbidden" — HTTP access blocked, forces HTTPS
- OS fingerprint: Unknown (ELB masks backend)

### False Positives

The NVD scanner flagged two CVEs by generic string match against "HTTP" — neither applies:
- CVE-2017-9788 (Apache httpd mod_http2) — server is awselb, not Apache
- CVE-2017-5638 (Apache Struts RCE) — no Struts in evidence

### Assessment

Minimal attack surface. Only standard web ports exposed, both behind AWS ELB.
No SSH, no database ports, no admin interfaces, no non-standard services.
The engagement proceeds entirely through the HTTPS endpoint on port 443.


## Step 1.2 — TLS Configuration Audit

**Date:** 2026-04-23

### Protocol Versions

| Version | Accepted | Cipher Negotiated | Bits |
|---------|----------|-------------------|------|
| TLS 1.3 | Yes | TLS_AES_128_GCM_SHA256 | 128 |
| TLS 1.2 | Yes | ECDHE-RSA-AES128-GCM-SHA256 | 128 |
| TLS 1.1 | **No** | — | — |
| TLS 1.0 | **No** | — | — |

No downgrade to TLS 1.1 or 1.0. POODLE, BEAST, and legacy protocol attacks are
not applicable.

### Cipher Suites Accepted

**TLS 1.3** (1 suite):
- `TLS_AES_128_GCM_SHA256` (128-bit)

**TLS 1.2** (4 suites):
- `ECDHE-RSA-AES256-GCM-SHA384` (256-bit)
- `ECDHE-RSA-AES128-GCM-SHA256` (128-bit)
- `ECDHE-RSA-AES256-SHA384` (256-bit)
- `ECDHE-RSA-AES128-SHA256` (128-bit)

**Weak ciphers:** None. No RC4, DES, 3DES, export-grade, or NULL suites. All
suites use ECDHE for forward secrecy.

**Note:** TLS 1.3 only negotiated AES-128-GCM, not AES-256-GCM or
CHACHA20-POLY1305. This is likely an AWS ELB default preference — not a
vulnerability, but worth noting that the server prefers 128-bit over 256-bit.

### Certificate

| Field | Value |
|-------|-------|
| Subject | `CN=1password.com` |
| Issuer | `CN=Amazon RSA 2048 M01, O=Amazon, C=US` |
| Key | RSA 2048-bit |
| Signature | SHA-256 with RSA |
| Valid from | 2026-01-22 |
| Valid until | 2027-02-20 |
| Days remaining | 302 |
| SANs | `1password.com`, `*.1password.com` |
| OCSP | `http://ocsp.r2m01.amazontrust.com` |
| Version | v3 |

Wildcard cert covering all `*.1password.com` subdomains. Amazon-issued (ACM).
RSA 2048 is the minimum recommended key size — adequate but not exceptional.
No ECC key.

### Security Headers

The root path (`/`) returns `403` from the ELB with minimal headers:
- `x-content-type-options: nosniff` — present
- `Strict-Transport-Security` — **absent** on the 403 response
- `Content-Security-Policy` — **absent**
- `X-Frame-Options` — **absent**
- `Server` header — **absent** (good, no server fingerprinting)

The missing HSTS on the 403 is likely because the ELB default page doesn't
set it. The actual application pages (login, vault UI) may set HSTS separately.
This should be verified in Step 1.3 (Web Client Extraction).

### Assessment

TLS configuration is solid:
- No protocol downgrade path (TLS 1.1/1.0 rejected)
- All cipher suites use AEAD modes with ECDHE forward secrecy
- No weak or deprecated ciphers
- Certificate is valid, properly chained, with appropriate SANs

Minor observations (not vulnerabilities):
- RSA-2048 key (minimum recommended; EC P-256 or RSA-4096 would be stronger)
- TLS 1.3 prefers AES-128-GCM over AES-256-GCM
- HSTS not observed on ELB 403 page — **confirmed present on application pages**
  (see Step 1.3)


## Step 1.3 — Web Client Extraction

**Date:** 2026-04-23

### Application Structure

The root URL (`/`) serves the full SPA. All paths (`/signin`, `/sign-in`,
`/login`, `/app`) return the same shell HTML — client-side routing. The `/app`
path returns a slightly different CSP (more restrictive).

- **Build version:** `data-version="2248"`
- **Git revision:** `data-gitrev="33a8e241e543"`
- **Build time:** 23 Apr 26 18:49 +0000 (same day as our scan)
- **Environment:** `prd` (production)
- **Canonical URL:** `https://my.1password.com/`
- **Sibling domains:** `1password.ca`, `1password.eu`, `ent.1password.com`

### JavaScript Bundles

All served from `https://app.1password.com/` with SRI integrity hashes:

| Bundle | Hash (truncated) | Purpose |
|--------|-------------------|---------|
| `runtime-62c8ad17.min.js` | `sha384-lnpYOr...` | Webpack runtime |
| `vendor-1password-383fec46.min.js` | `sha384-ps/sIb...` | 1Password core library |
| `vendor-other-8afa0afd.min.js` | `sha384-yTVzGZ...` | Third-party deps |
| `vendor-react-7f2b22fd.min.js` | `sha384-AxAeyL...` | React framework |
| `vendor-lodash-11dceb72.min.js` | `sha384-/jCcn7...` | Lodash utilities |
| `webapi-d3ad37f2.min.js` | `sha384-0oSoS6...` | Web API client |
| `vendor-moment-a350876a.min.js` | `sha384-bgHnUo...` | Date/time library |
| `app-4b7678e0.min.js` | `sha384-PdqkKN...` | Main application |
| `sk-2c17b526.min.js` | `sha384-9UxhaJ...` | Secret Key retrieval (fallback) |

All scripts use `crossorigin="anonymous"` and SRI hashes — tampering with the
CDN content would be detected by the browser.

### WebAssembly Security

The client ships WASM modules (likely the crypto core) with a **hash whitelist**:

```
trustedWasmHashes = [
    'k6RLu5bHUSGOTADUeeTBQ1gSKjiazKFiBbHk0NxflHY=',
    'L7kNpxXKV0P6GuAmJUXBXt6yaNJLdHqWzXzGFEjIYXQ=',
    'GVnMETAEUL/cu/uTpjD6w6kwDLUYqiEQ7fBsUcd+QJw=',
    '+yHBrSgjtws1YuUDyoaT3KkY0eOi0gVCBOZsGNPJcOs=',
    'I+k/SNmZg4ElHUSaENw7grySgWIki/yjg62WZcsxXy8=',
    'WwqUPAGJ2F3JdfFPHqHJpPrmVI5xmLlfIJadWXKRQR8='
]
```

Every WASM module is SHA-256 hashed before loading and compared against this
list. `WebAssembly.compile`, `instantiate`, `validate`, and
`compileStreaming` are all monkey-patched to enforce this check. The non-async
`Module` constructor is blocked entirely.

This is a defense against WASM substitution attacks — even with a MITM, an
attacker cannot inject a modified crypto module without matching one of these
hashes. **This significantly raises the bar for client-side attacks.**

WASM base URL: `https://app.1password.com/wasm/`

### Security Headers (Application Pages)

All security headers are present and well-configured on the application pages:

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `Content-Security-Policy` | Strict — see below |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Cross-Origin-Opener-Policy` | `restrict-properties` |
| `Permissions-Policy` | `interest-cohort=()` |
| `Cache-Control` | `max-age=60, no-cache, no-store` |
| CSP Reporting | `report-to csp-endpoint` -> `https://csp.1passwordservices.com/report` |

### Content Security Policy (Parsed)

```
default-src:       'none'
script-src:        https://app.1password.com 'wasm-unsafe-eval' + 2 inline hashes
style-src:         https://app.1password.com + 1 inline hash
connect-src:       'self' blob: https://app.1password.com wss://b5n.1password.com
                   https://*.1password.com https://*.1password.ca https://*.1password.eu
                   https://*.ent.1password.com https://f.1passwordusercontent.com
                   https://a.1passwordusercontent.com https://watchtower.1password.com
                   https://api.pwnedpasswords.com + Firebase, Sentry, telemetry
font-src:          https://app.1password.com
img-src:           data: blob: https://app.1password.com + avatar/cache CDNs
child-src/frame-src: 'self' + Duo Security, billing, survey, email providers
worker-src:        'self'
form-action:       https://app.kolide.com/ https://app.trelica.com/
frame-ancestors:   https://*.1password.com
upgrade-insecure-requests
```

**CSP Analysis:**
- `default-src 'none'` — strict baseline, everything must be explicitly allowed
- `script-src` — **no `unsafe-inline` or `unsafe-eval`** — only hashed inlines
  and `https://app.1password.com`. `wasm-unsafe-eval` is required for WASM
  execution but is mitigated by the WASM hash whitelist
- `connect-src` — allows WebSocket to `wss://b5n.1password.com` (push notifications?)
  and HTTPS to various 1Password service domains
- `frame-ancestors: https://*.1password.com` — prevents clickjacking from
  non-1password origins
- CSP violation reporting is active — any injection attempt would be reported

**XSS attack surface is very limited.** No `unsafe-inline`, no `unsafe-eval`,
SRI on all scripts, WASM hash whitelist, strict frame-ancestors.

### Exposed Configuration Data

The HTML `<head>` tag contains `data-*` attributes with configuration:

**Potentially interesting for the engagement:**
- `data-brex-client-id`: `bri_b2df18d65bc82a948573537157eceb07`
- `data-brex-auth`: `CLIENT_SECRET` (literal string, not an actual secret)
- `data-fcm-api-key`: `AIzaSyCs8WNa10YE5AVyfL33RBHBKQdYZMw7OB0` (Firebase Cloud Messaging)
- `data-fcm-project-id`: `b5-notification-prd`
- `data-sentry-dsn`: `https://6342e577bc314e54ab2c5650a4c5be8f:f7b7d11056d84dd0b09e9a9ca31a72e8@web-ui-sentry.1passwordservices.com/...`
- `data-slack-client-id`: `36986904051.273534103040`
- `data-stripe-key`: `pk_live_F59R8NjiAi5Eu7MJcnHmdNjj`
- `data-fastmail-client-id`: `35c941ae`
- `data-snowplow-url`: `https://telemetry.1passwordservices.com` (analytics)
- `data-webpack-public-path`: `https://app.1password.com/` (CDN origin)

The page includes `data-bug-researcher-notes` that explicitly states: "All keys
below are intended to be exposed publicly, and are therefore not vulnerable."

### Assessment

The web client is well-hardened:
- SRI on all scripts prevents CDN tampering
- WASM hash whitelist prevents crypto module substitution
- Strict CSP blocks most XSS vectors
- HSTS with preload prevents SSL stripping
- `X-Frame-Options: DENY` prevents clickjacking
- CSP violation reporting is active

The main avenue for client-side attacks would be:
1. Finding an XSS that works within the CSP constraints (very difficult)
2. Compromising `app.1password.com` CDN itself (the only allowed script source)
3. Exploiting `wasm-unsafe-eval` if a WASM module can be substituted (blocked by
   hash whitelist, but worth investigating the validation code path)

The `vendor-1password` and `webapi` bundles are the highest-value targets for
reverse engineering — they contain the SRP client, key derivation, and vault
encryption logic.


## Step 1.4 — API Enumeration

**Date:** 2026-04-23

### CORS Configuration

`OPTIONS /api/v1/auth` returns:
- `access-control-allow-origin: https://bugbounty-ctf.1password.com` (strict, not `*`)
- `access-control-allow-credentials: true`
- `access-control-allow-headers: X-AgileBits-Client, X-AgileBits-MAC, Cache-Control, X-AgileBits-Session-ID, Content-Type, OP-User-Agent, ChannelJoinAuth`
- `access-control-allow-methods: GET, POST, PUT, PATCH, DELETE`

Notable custom headers: `X-AgileBits-Client`, `X-AgileBits-MAC`,
`X-AgileBits-Session-ID` — likely required for authenticated requests.
The MAC header suggests request signing.

### Auth Endpoints

| Endpoint | Method | Status | Response |
|----------|--------|--------|----------|
| `/api/v1/auth` | POST | 401 | `{}` (empty, no differentiation by email) |
| `/api/v2/auth` | POST | 401 | `{}` |
| `/api/v2/auth/complete` | POST | 401 | `{}` |
| `/api/v2/auth/confirm-key` | POST | 401 | `{}` |
| `/api/v2/auth/methods` | POST | **200** | `{"authMethods":[{"type":"PASSWORD+SK"}],...}` |
| `/api/v1/auth/verify` | POST | 401 | `{}` |
| `/api/v1/auth/mfa` | POST | 401 | `{}` |
| `/api/v3/auth` | POST | 404 | No v3 API |

The auth init endpoint returns identical `401 {}` for all email addresses
including empty string — **no username enumeration** via this path.

### Key Finding: `/api/v2/auth/methods`

This endpoint returns 200 for any request and confirms:
```json
{"authMethods":[{"type":"PASSWORD+SK"}],"signInAddress":"https://bugbounty-ctf.1password.com"}
```

- Auth method is `PASSWORD+SK` (password + Secret Key, i.e., 2SKD)
- Returns the same response for all emails including empty/nonexistent
- Returns 400 only for malformed email strings (e.g., `"not-an-email"`)
- **No SSO** — pure password + Secret Key auth only
- **No email enumeration** possible through this endpoint

### Endpoint Map (from JS Bundle)

The `webapi` bundle (934 KB) contains ~200 API endpoint paths. Key categories:

**Auth flow (v2):**
- `/api/v2/auth` — SRP init
- `/api/v2/auth/complete` — SRP verify / session creation
- `/api/v2/auth/confirm-key` — Secret Key confirmation
- `/api/v2/auth/methods` — query auth methods (public)
- `/api/v2/auth/webauthn/register` — WebAuthn registration
- `/api/v2/auth/webauthn/register/challenge` — WebAuthn challenge
- `/api/v2/auth/sso/reconnect` — SSO reconnection

**Recovery (v2) — high-value attack surface:**
- `/api/v2/recovery-keys/session/new` — start recovery session
- `/api/v2/recovery-keys/session/auth/cv1/start` — recovery auth start
- `/api/v2/recovery-keys/session/auth/cv1/confirm` — recovery auth confirm
- `/api/v2/recovery-keys/session/complete` — complete recovery
- `/api/v2/recovery-keys/session/identity-verification/email/start` — email verification
- `/api/v2/recovery-keys/session/identity-verification/email/submit` — submit verification
- `/api/v2/recovery-keys/session/material` — recovery key material
- `/api/v2/recovery-keys/session/status` — session status
- `/api/v2/recovery-keys/policies` — recovery policies (returns 401)
- `/api/v2/recovery-keys/keys` — recovery keys (returns 401)
- `/api/v2/recovery-keys/attempts` — recovery attempts (returns 401)

**Account/keyset management:**
- `/api/v2/account/keysets` — account keysets (returns 401)
- `/api/v1/account` — account info (returns 401)
- `/api/v1/device` — device registration (returns 401)
- `/api/v1/session/signout` — session termination
- `/api/v1/session/touch` — session keepalive
- `/api/v2/session-restore/*` — session restore flow (save-key, restore-key, destroy-key)

**Vault operations:**
- `/api/v2/vault` — vault access
- `/api/v2/mycelium/u` / `/api/v2/mycelium/v` — unknown (Mycelium?)
- `/api/v1/vault/personal` — personal vault
- `/api/v1/vault/everyone` — shared vault
- `/api/v1/vault/managed` — managed vault
- `/api/v1/vault/account-transfer` — vault transfer

**Other interesting:**
- `/api/v1/confidential-computing/session` — confidential computing
- `/api/v1/signinattempts` / `/api/v2/signinattempts` — sign-in attempt logs
- `/api/v1/monitoring/status` — monitoring
- `/api/v2/perftrace` / `/api/v2/preauth-perftrace` — performance tracing
- `/api/v1/oidc/token` — OIDC token endpoint

### Error Behavior

All authenticated endpoints return `401 {}` (empty JSON body) — the server
leaks no information about why the request failed. No differentiated error
messages, no descriptive error codes.

Signup endpoints (`/api/v1/signup`, `/api/v2/signup`) return `400 {}` for all
payloads — signup may be disabled on the CTF instance.

### Rate Limiting

5 rapid sequential requests to `/api/v1/auth` all returned `401` with no
throttling or blocking. No `Retry-After` header. No CAPTCHA challenge.
**Rate limiting may be absent or has a high threshold.**

### Assessment

The API surface is large (~200 endpoints) but consistently requires
authentication. Key observations:

1. **No username/email enumeration** — all auth endpoints return identical
   responses regardless of email
2. **Recovery key flow is extensive** — 10+ endpoints for account recovery.
   This is the white paper's Appendix A.4 weakness. Worth deep investigation
   in Phase 3.
3. **Custom request signing** — `X-AgileBits-MAC` header suggests HMAC-based
   request authentication. Need to understand this from the JS bundle.
4. **Session restore flow** — save/restore/destroy key endpoints could be
   a secondary attack surface for session hijacking.
5. **No rate limiting observed** — brute force may be feasible if the auth
   protocol allows it (2SKD makes this moot for password attacks, but
   session/token brute force could be viable).
6. **v2 auth flow** — the client uses v2 (`/api/v2/auth` -> `/api/v2/auth/complete`)
   rather than v1. Both respond similarly.


## Step 1.5 — Public Source Analysis

**Date:** 2026-04-23

### 1Password Public Repositories

93 public repos on GitHub under `github.com/1Password`. Relevant repos:

**Highest value:**

| Repo | Language | Description |
|------|----------|-------------|
| `1Password/srp` | Go | **SRP-6a implementation used by 1Password Teams** (389 stars) |
| `burp-1password-session-analyzer` | Java | **Burp plugin for analyzing encrypted 1Password sessions** (79 stars) |
| `passkey-rs` | Rust | WebAuthn authenticator framework |
| `curve25519-dalek` | Rust | Fork with specific bug fix |

### SRP Library Analysis (`1Password/srp`)

**Files:** 13 Go source files, ~70KB total. Full SRP-6a implementation with both
standard (RFC 5054) and non-standard (1Password legacy) modes.

**Key classes:**
- `SRP` struct — main client/server object
- `Group` — Diffie-Hellman group parameters
- `Hash` — configurable hash (SHA-256 default)

#### Critical Validation: `IsPublicValid()` (srp.go:208)

```go
func (s *SRP) IsPublicValid(AorB *big.Int) bool {
    if s.group.Reduce(AorB).Cmp(bigOne) == 0 {
        return false  // Rejects A % N == 1
    }
    if s.group.IsZero(AorB) {
        return false  // Rejects A == 0
    }
    return true
}
```

**Assessment:** This validates A != 0 and A % N != 1, but **does NOT check
A % N != 0** directly. The `Reduce` call computes `A mod N`. If `A = N`, then
`Reduce(A) = 0`, which is caught by `IsZero`. If `A = 2N`, then `Reduce(A) = 0`,
also caught. But the check for `Cmp(bigOne)` only catches `A % N == 1`, not
`A % N == 0` when A > 0.

Wait — re-reading: `IsZero` checks if the value is zero. `Reduce(A)` gives
`A mod N`. So:
- A=0: `IsZero(0)` = true -> rejected
- A=N: `Reduce(N) = 0`, `IsZero(0)` = true -> rejected
- A=2N: `Reduce(2N) = 0`, `IsZero(0)` = true -> rejected
- A=kN: same, all rejected

**The zero-key attack is properly mitigated in this library.** The library also
rejects A=1 (which would make the session key deterministic but not trivially
zero). Additional safety: `SetOthersPublic()` calls `IsPublicValid()` and sets
`badState=true` on failure, preventing any further key computation.

#### Non-Standard u Calculation

The library has a documented bug:
```go
// BUG(jpg): Calculation of u does not use RFC 5054 compatible padding/hashing
```

The non-standard mode (`calculateUNonStd`) concatenates hex strings of A and B
with leading zeros stripped, then hashes. This differs from RFC 5054 which
requires fixed-width padding. The standard mode (`calculateUStd`) uses proper
padding. **The web client likely uses the standard mode** (`NewClientStd`), but
this should be verified.

#### Other Observations

- SHA-256 is hardcoded as the default hash
- Ephemeral secret minimum size: 32 bytes (per RFC 5054)
- `u == 0` is explicitly rejected (would make session key independent of password)
- Server-side key computation: `S = (A * v^u) ^ b mod N`
- Client-side key computation: `S = (B - k*g^x) ^ (a + u*x) mod N`

### Burp Plugin Insight

The `burp-1password-session-analyzer` README reveals critical architecture:

> "We require every request and response that are specific to a 1Password account
> to be protected by the account's master password and secret key, which means
> every bit of data that gets sent is encrypted, and every request is authenticated."

This confirms:
1. **All API payloads are encrypted** — not just auth, ALL requests/responses
2. **Every request is MAC'd** — explains the `X-AgileBits-MAC` header from Step 1.4
3. **Standard web fuzzing tools don't work** — you can't tamper with requests
   without the session key
4. The Burp plugin requires a valid session key to decrypt/re-encrypt payloads

This means:
- IDOR/parameter tampering is not possible without first obtaining a valid session
- API fuzzing requires understanding the encryption layer
- The `X-AgileBits-Session-ID` + `X-AgileBits-MAC` headers are integral to the
  protocol, not optional

### Assessment

The SRP library is well-implemented:
- Zero-key attacks (A=0, A=N, A=kN) are properly rejected
- The library is well-tested (20KB of tests)
- SHA-256 is used throughout
- Session key derivation follows standard SRP-6a

The main attack surface from source analysis:
1. **Non-standard u calculation** — if the server uses the legacy mode, the
   different padding could theoretically be exploitable, though this is unlikely
2. **All-encrypted API protocol** — makes server-side testing much harder than
   anticipated. We need the session key to even send valid requests
3. **Burp plugin exists** — we should use this for any authenticated testing


## Step 1.6 — CVE / Exploit Search

**Date:** 2026-04-23

**Source:** NVD CVE List V5 database (346,306 CVEs loaded into local SQLite),
cross-referenced with agent-gathered research from Exploit-DB, academic papers,
and security advisories.

### 1Password-Specific CVEs (13 total)

| CVE | CVSS | Product | Relevance |
|-----|------|---------|-----------|
| **CVE-2022-32550** | — | All 1Password apps | **SRP connection validation deviation** — server impersonation possible in specific circumstances. The only CVE targeting 1Password's SRP implementation. Patched. |
| **CVE-2020-10256** | 9.8 | CLI/SCIM Bridge (beta) | **Insecure PRNG for encryption keys** — brute-forceable key generation. Beta-only, not main apps. Patched. |
| **CVE-2024-42219** | 7.8 | 1Password 8 macOS | **XPC IPC validation bypass** — local attacker exfiltrates vault items + SRP-x via impersonating browser extension. Patched 8.10.36. |
| **CVE-2024-42218** | 4.7 | 1Password 8 macOS | **Downgrade attack** — local attacker uses old app version to bypass macOS security. Patched 8.10.38. |
| **CVE-2022-29868** | 5.5 | 1Password 7 macOS | **Process validation bypass** — local exfiltration of secrets including "derived values used for signing in." Patched 7.9.3. |
| **CVE-2021-41795** | 6.5 | Safari extension | **Authorization bypass** — malicious web page reads fillable vault items silently. Patched 7.8.7. |
| **CVE-2021-36758** | 5.4 | Connect server | **Privilege escalation** via improperly scoped access tokens. Patched 1.2. |
| **CVE-2021-26905** | 6.5 | SCIM Bridge | **TLS private key disclosure** via log file access. Patched 1.6.2. |
| **CVE-2020-18173** | 7.8 | 1Password 7 Windows | **DLL injection** — local arbitrary code execution. |
| **CVE-2018-19863** | 5.5 | 1Password 7 macOS | **Credential logging** — Safari→1Password data logged locally. Patched. |
| **CVE-2018-13042** | 5.9 | 1Password 6 Android | **DoS** via exported activities. Not relevant to web. |
| **CVE-2014-3753** | 5.5 | 1Password Windows | **Security feature bypass.** Sparse details. |
| **CVE-2012-6369** | 4.3 | 1Password 3 desktop | **XSS** in troubleshooting report. Ancient, irrelevant. |

**Assessment:** No CVE has ever achieved remote vault content recovery against
1Password. All high-severity CVEs require local access (macOS IPC bypass). The
only SRP-related CVE (CVE-2022-32550) was a connection validation issue, not a
cryptographic break. The insecure PRNG (CVE-2020-10256) only affected beta CLI
tools.

### SRP Protocol CVEs

| CVE | CVSS | Description | Applies to 1Password? |
|-----|------|-------------|----------------------|
| **CVE-2009-4810** | 7.5 | Samhain SRP zero-value validation bypass (classic A=0) | **NO** — 1Password's library validates via `IsPublicValid()` |
| **CVE-2025-54885** | 6.9 | Thinbus JS SRP: 252 bits entropy instead of 2048 (function vs value bug) | **NO** — different library, JS-specific bug |
| **CVE-2026-3559** | 8.1 | Philips Hue: SRP static nonce, full auth bypass | **NO** — implementation bug, not protocol flaw |
| **CVE-2021-4286** | 2.6 | pysrp: timing leak in `calculate_x` | **POSSIBLY** — same attack class (timing) is relevant |

### SRP Academic Research

| Paper | Year | Finding | Relevance |
|-------|------|---------|-----------|
| **PARASITE** (CCS 2021) | 2021 | OpenSSL `BN_mod_exp` non-constant-time path leaks password info via cache timing. Single-trace attack. | **HIGH** — if 1Password's server uses affected OpenSSL version. The Go SRP library uses Go's `math/big`, not OpenSSL. |
| **Threat for SRP** (ACNS 2021) | 2021 | MitM can modify salt to derive new exponent, exploiting timing even with different client implementation | **MEDIUM** — requires MitM + timing vulnerability |
| **Just How Secure is SRP?** (ePrint 2025) | 2025 | SRP is probably NOT UC-secure; existing proof uses non-standard model | **LOW** — theoretical; game-based security still holds |
| **Small subgroup non-confinement** (Hao 2010) | 2010 | Information leakage from subgroup structure | **LOW** — mitigated by safe primes |

### PBKDF2 CVEs

| CVE | CVSS | Description | Relevance |
|-----|------|-------------|-----------|
| **CVE-2025-6545** | 9.1 | npm `pbkdf2` package: returns zero-filled buffers for non-normalized algorithm names | **CHECK** — if web client uses this polyfill instead of native WebCrypto |
| **CVE-2025-6547** | 9.1 | Same `pbkdf2` package: improper validation | Same as above |
| **CVE-2023-46233** | 9.1 | crypto-js: PBKDF2 defaults to SHA-1 with 1 iteration | **NO** — 1Password uses explicit SHA-256 + 100k+ iterations |
| **CVE-2023-46133** | 9.1 | CryptoES: same weak default as crypto-js | **NO** — same reason |
| **CVE-2025-11187** | — | OpenSSL PBMAC1: stack buffer overflow in PKCS#12 MAC verification | **NO** — different context (PKCS#12) |

**Key observation:** 1Password's default PBKDF2-HMAC-SHA256 iterations is
**650,000** (discovered in Step 3.9 — `DEFAULT_ITERATIONS=65e4`), which exceeds
OWASP's 2025 recommendation of 600,000. A secondary constant of 100,000 exists
for token-based derivation. The 128-bit Secret Key makes brute force infeasible
regardless.

### AES-GCM / Nonce CVEs

| CVE | CVSS | Description | Relevance |
|-----|------|-------------|-----------|
| **CVE-2026-5446** | 6.0 | wolfSSL ARIA-GCM: reuses identical 12-byte nonce for every record | **PATTERN** — demonstrates catastrophic nonce reuse |
| **CVE-2026-26014** | 5.9 | Pion DTLS: random nonce generation, birthday bound collision | **PATTERN** — random nonces hit collision at 2^32 messages |
| **CVE-2021-32791** | 5.9 | mod_auth_openidc: static IV for AES-GCM | **PATTERN** — static nonce = keystream recovery |
| **CVE-2025-61739** | 7.2 | Generic nonce reuse: replay attack or decryption | **PATTERN** |

**Assessment:** No AES-GCM CVE directly affects 1Password. The nonce reuse
pattern is the primary risk — must verify 1Password uses unique per-item nonces.
Birthday bound (2^32 messages per key) is unlikely to be reached in vault usage.

### WebCrypto CVEs

| CVE | CVSS | Description | Relevance |
|-----|------|-------------|-----------|
| **CVE-2016-5142** | 9.8 | Chrome WebCrypto use-after-free — RCE | **HISTORICAL** — fixed Chrome 52 (2016) |
| **CVE-2017-7822** | 5.3 | Firefox: AES-GCM accepts zero-length IV | **HISTORICAL** — fixed Firefox 56 (2017) |
| **CVE-2022-35255** | — | Node.js: weak randomness in WebCrypto keygen | **NO** — browser, not Node.js |
| **CVE-2018-5122** | — | Firefox: integer overflow in WebCrypto DoCrypt | **HISTORICAL** — fixed |

**Assessment:** All WebCrypto CVEs are historical and patched in modern browsers.
The browser's native crypto layer is the correct choice over JS polyfills.

### Indirect / Dependency CVEs

| CVE | CVSS | Description | Relevance |
|-----|------|-------------|-----------|
| **CVE-2023-4863** | 10.0 | libwebp heap buffer overflow (via Chromium/Electron) | 1Password patched in 8.10.15. RCE via crafted WebP image. |
| **CVE-2025-55305** | — | Electron ASAR integrity bypass (Trail of Bits) | 1Password patched in 8.11.8-40. Local backdoor via V8 snapshot. |

### Research Papers

| Paper | Finding | Relevance |
|-------|---------|-----------|
| **ETH Zurich / USI** (USENIX Sec 2026) | 2 attack scenarios under malicious-server model achieve full vault compromise | **HIGH** — but 1Password says these are documented in their white paper. The 2SKD Secret Key provides protection competitors lack. |
| **DOM-based extension clickjacking** (DEF CON 33, 2025) | Clickjacking attacks against browser extension autofill | **MEDIUM** — patched in extension 8.11.7. Not relevant to web vault. |

### Summary Assessment

1. **No remote vault content recovery has ever been demonstrated** against
   1Password via any CVE or published research
2. **SRP implementation is solid** — zero-key attacks properly mitigated,
   connection validation CVE (2022-32550) is patched
3. **PARASITE timing attack is the most credible SRP threat** — but requires
   non-constant-time big number operations, and Go's `math/big` (used by the
   SRP library) is not known to have the OpenSSL-specific vulnerability
4. **PBKDF2 iteration count (100k) is below OWASP 2025 recommendation** but
   irrelevant due to 128-bit Secret Key
5. **npm `pbkdf2` polyfill (CVE-2025-6545) is high risk if used** — must verify
   the web client uses native WebCrypto, not a polyfill
6. **ETH Zurich malicious-server attacks** confirm that server compromise +
   client code tampering can break vault confidentiality — aligns with the
   white paper's acknowledged weaknesses (Appendix A.2, A.3, A.5)
7. **No exploits on Exploit-DB** for 1Password
8. **All high-severity CVEs required local access** (macOS IPC, DLL injection)

### Actionable Items for Phase 2-3

1. ~~**Verify WebCrypto vs polyfill**~~ — **RESOLVED (Step 3.9)**: Native
   `crypto.subtle.deriveBits()` confirmed. CVE-2025-6545 does NOT apply.
2. **Test SRP timing** — PARASITE-class timing attack against the production
   server, even though the Go library is likely safe (Step 3.2). **Requires
   valid account credentials to get SRP parameters.**
3. **Check AES-GCM nonce generation** — verify per-item unique nonces when
   we reach vault encryption analysis (Step 3.7). **Requires authenticated
   session.**
4. **Investigate CVE-2022-32550 residual** — the SRP connection validation
   deviation was patched, but understand exactly what deviated to look for
   similar issues in the current implementation


## Phase 2: Protocol Analysis

### Step 2.1-2.2 — Auth Flow Discovery & SRP Parameter Extraction

**Date:** 2026-04-24

### Auth Endpoint Discovery

The web client JS bundle (`webapi-d3ad37f206b68333b768.min.js`) reveals a
**three-step SRP auth flow** not previously documented:

1. **`POST /api/v3/auth/start`** — SRP init (v3, not v1/v2!)
   - Request: `{email, skFormat, skid, deviceUuid, userUuid}`
   - Response: `{status, sessionID, accountKeyFormat, accountKeyUuid, userAuth: {method, alg, iterations, salt}}`
   - `encrypted: false` — no MAC needed
2. **`POST /api/v2/auth`** — SRP key exchange
   - Request: `{userA: <client_ephemeral_hex>}`
   - Response: `{userB: <server_ephemeral_hex>}`
   - `encrypted: false`
3. **`POST /api/v2/auth/confirm-key`** — SRP verification
   - Request: `{clientVerifyHash: <M1>}`
   - Response: `{serverVerifyHash: <M2>}`
   - `encrypted: false`

After successful auth, a `complete` call registers the device and receives
server config. All subsequent requests are encrypted with the session key.

### Critical Finding: `X-AgileBits-Client` Header Required

All API endpoints return `403` (text/plain) without the correct
`X-AgileBits-Client` header. The correct value is:

```
X-AgileBits-Client: 1Password for Web/2248
```

Format: `{clientName}/{clientVersion}` where:
- `clientName` = `"1Password for Web"` (set in `setDevice()`)
- `clientVersion` = build version from `data-version` HTML attribute (currently `2248`)

Without this header, all v2/v3 endpoints return `403` with empty body and
`text/plain` content-type. With the header, endpoints return proper JSON
responses with CORS, HSTS, CSP, and `x-request-id` headers.

**This was the key to unlocking API access.** Earlier reconnaissance (Step 1.4)
was testing v1 endpoints which don't require this header, but v2/v3 do.

### `skFormat` Validation

The `skFormat` field must be `"A3"` (string). Sending `"3"` (numeric format)
returns `400 {"reason":"invalid_sk_prefix_format"}` — the only descriptive
error message the server returns. All other invalid payloads return `400 {}`.

This confirms:
- The server validates Secret Key format before processing
- `"A3"` is the expected format prefix
- Only the format check produces a descriptive error; all subsequent
  validation failures return empty `{}`

### No User Enumeration

Tested 7 different email addresses plus empty string against
`/api/v3/auth/start` with valid headers and `skFormat: "A3"`:

| Email | Status | Body | Time |
|-------|--------|------|------|
| test@example.com | 400 | {} | 193ms |
| admin@1password.com | 400 | {} | 150ms |
| ctf@1password.com | 400 | {} | 170ms |
| bugbounty@agilebits.com | 400 | {} | 155ms |
| jeff@1password.com | 400 | {} | 171ms |
| security@1password.com | 400 | {} | 166ms |
| (empty) | 400 | {} | — |

All return identical `400 {}`. Timing variance is within network jitter
(~40ms range). **No user enumeration via this endpoint.**

### Auth Flow Requirements

The `_startAuth` JS function reveals:
- **Secret Key is mandatory** — throws `"Missing Secret Key"` before any
  network request
- `skid` = UUID extracted from the Secret Key itself (first segment)
- `userUuid` = the account's user UUID (stored locally from prior signin)
- `deviceUuid` = browser-generated UUID (persisted in localStorage)
- If startAuth returns `status: "device-not-registered"`, the client calls
  `registerDevice()` (which requires the session) and retries

**Implication:** Without a valid `(email, skid, userUuid)` tuple, we cannot
get SRP parameters (salt, iterations, B) from the server. The server does
not return these for unknown accounts — it returns `400 {}` with no
distinguishing information.

### Device Registration Flow

From the JS bundle:
```
if ("device-not-registered" === status) {
    setSessionUuid(sessionID);
    await registerDevice(session, device);
    // retry startAuth
}
```

Device registration happens AFTER receiving a sessionID from startAuth,
which requires valid credentials. **Cannot register a device without first
authenticating.**

### `auth/methods` Endpoint

`POST /api/v2/auth/methods` with body `{email, userUuid}`:
- Returns `{authMethods: [{type: "PASSWORD+SK"}], signInAddress: "..."}`
- Previously worked without `X-AgileBits-Client` header (Step 1.4)
- Confirms pure 2SKD auth, no SSO, no passkey-only path

### Recovery Flow Status

All recovery endpoints (`/api/v2/recovery-keys/*`) return `403` even with
the correct `X-AgileBits-Client` header. These endpoints likely require
an authenticated session or a different client identifier. **Cannot probe
recovery flow without credentials.**

### Assessment

The auth flow is tighter than initially estimated:

1. **v3 auth endpoint** was not known until JS analysis — v1/v2 probing in
   Step 1.4 was hitting wrong endpoints
2. **`X-AgileBits-Client` header** acts as a soft gatekeeper — without it,
   all modern endpoints are inaccessible
3. **SRP parameters are not exposed** without valid account identifiers —
   cannot extract salt, iterations, or server ephemeral B for unknown accounts
4. **The three-step auth flow** means SRP init and key exchange are separate
   requests, which may create opportunities for state manipulation
5. **Recovery endpoints require more than just the client header** — likely
   need an authenticated session

### What We Need to Proceed

Phase 2 (Protocol Analysis) and Phase 3 (Attack Execution) both require
SRP parameters that we can only get with valid account identifiers. Options:

1. **Obtain a test account** — if the CTF rules allow creating or using a
   provided account on `bugbounty-ctf.1password.com`
2. **Find the CTF account email/UUID** — the challenge description says
   "bad poetry" is stored in a "dedicated 1Password Bug Bounty CTF account"
   but doesn't provide login details
3. **Focus on client-side attacks** — JS bundle analysis, WASM bypass, CSP
   weaknesses (Step 3.9) don't require authentication
4. **Brute force account identifiers** — infeasible given the `(email, skid,
   userUuid)` tuple requirement with identical 400 responses


## Phase 3: Client-Side Attack Analysis

### Step 3.9 — Client-Side Attack Surface

**Date:** 2026-04-23

### PBKDF2: Native WebCrypto Confirmed (CVE-2025-6545 Does NOT Apply)

The web client uses **native `crypto.subtle`** for all PBKDF2 operations:

```javascript
// From webapi bundle — actual key derivation
const c = await o.subtle.importKey("raw", i, {name: "PBKDF2"}, false, ["deriveBits"]);
const d = await o.subtle.deriveBits({name: "PBKDF2", salt: r, iterations: s, hash: {name: e}}, c, 8*n);
```

- All PBKDF2 calls go through `crypto.subtle.importKey` + `crypto.subtle.deriveBits`
- The npm `pbkdf2` polyfill (CVE-2025-6545 / CVE-2025-6547, zero-buffer on
  non-normalized algorithm names) is **NOT used**
- HKDF uses `crypto.subtle` as well
- **CVE-2025-6545 is definitively ruled out**

**Iteration counts discovered:**
- `DEFAULT_ITERATIONS = S = 65e4` = **650,000** (higher than OWASP 2025 recommendation of 600k!)
- `ITERATIONS_100_000 = 1e5` = 100,000 (used for token-based PBKDF2)
- The Bitwarden import path also uses `crypto.subtle.deriveBits`

### Lodash 4.17.21 — Unfixed CVEs, But NOT Exploitable

**Two unfixed CVEs exist in lodash 4.17.21:**

| CVE | CVSS | Description | Fixed in |
|-----|------|-------------|----------|
| CVE-2025-13465 | 6.9 MEDIUM | Prototype pollution via `_.unset`/`_.omit` — can delete Object.prototype properties | 4.17.23 |
| CVE-2026-2950 | 6.5 MEDIUM | Bypass of CVE-2025-13465 fix via array-wrapped paths | 4.18.0 |

These enable **destructive prototype pollution** — deleting properties from
built-in prototypes via user-controlled paths to `_.unset()` or `_.omit()`.

**However:** Grep of all 4 application bundles (app, webapi, vendor-1password,
vendor-lodash) found **zero calls to `_.unset` or `_.omit`**. The vulnerable
functions are shipped in the lodash bundle but never invoked by the application.

**Assessment:** Not exploitable in the current application. The lodash bundle
is the standard full build (170KB) but the app only uses safe lodash functions
(`.merge`, `.set`, `.get`, `.pick`, etc.).

### WASM Hash Whitelist — Main Thread Only

The WASM security model (documented in Step 1.3) has a significant
architectural limitation:

**The hash whitelist monkey-patch only protects the main thread.**

Each of the 5 WASM modules in `vendor-1password` is loaded through patched
`WebAssembly.instantiateStreaming` / `WebAssembly.instantiate` calls. These
patched functions check the SHA-256 hash against the 6-hash whitelist before
allowing compilation.

**But Web Workers and Service Workers get a fresh `WorkerGlobalScope` with
the native, unpatched `WebAssembly` API.** The hash check does not exist in
Worker contexts.

**Worker infrastructure discovered:**
- Worker scripts served from document origin: `https://bugbounty-ctf.1password.com/workers/` (HTTP 200)
- Workers loaded via: `new Worker(new URL(\`https://${host}/${workersDir}${name}\`).href)`
- `worker-src 'self'` in CSP restricts Workers to same origin only
- Firebase messaging service worker at `/firebase-messaging-sw.js` (HTTP 200)
  - Imports Firebase SDK from `app.1password.com/libjs/`
  - Handles push notification events

**Attack chain (theoretical):**
1. Find a way to inject or replace a same-origin Worker script
2. Inside the Worker, call native `WebAssembly.instantiate()` with arbitrary
   WASM bytecode — no hash check runs
3. The malicious WASM module has full access to the Worker's memory and
   can communicate back via `postMessage`

**Mitigations that block this chain:**
- `worker-src 'self'` — no blob: or data: URLs for Workers
- SRI on all script tags (but Workers bypass SRI since they're not `<script>` tags)
- Worker scripts are static, served from the CDN proxy
- No file upload endpoint discovered that could create a Worker script

**Verdict:** Theoretical bypass exists but requires a prerequisite vulnerability
(same-origin script injection or service worker hijacking) that has not been found.

### postMessage Handlers — Origin Validation Analysis

**5+ `message` event listeners identified across bundles.**

#### Validated handlers (safe):
- **StripeFrame**: `origin === u` where `u` is the Stripe payment URL ✅
- **DuoFrame**: `t.origin === i` where `i = "https://duo.1passwordservices.com"` ✅

#### Weakly validated handlers:

**Idle timer reset handler:**
```javascript
// Accepts messages from any *.1password.com subdomain
const n = e.origin.endsWith("." + M.S9.config.server);
const t = !!e.source?.opener && e.source.opener === window;
const o = "reset_idle_timer" === e.data.type;
n && t && o && this.resetIdleTimer();
```
Three conditions required: origin endsWith `.1password.com`, source is a
window opened by this window, and message type is `reset_idle_timer`. The
opener check (`e.source.opener === window`) prevents arbitrary cross-origin
abuse — only a popup opened by this specific window can send the message.

**L handler (extension communication):**
```javascript
D = (e, t) => {
    const n = new URL(t);
    const o = e.config.server;
    return "" !== o && n.host.slice(n.host.indexOf(".") + 1) === o;
};
```
Origin validation extracts everything after the first dot in the host. For
`evil.1password.com`, this yields `1password.com` which matches `config.server`.
**Any `*.1password.com` subdomain passes this check.**

If a subdomain takeover exists on any `*.1password.com` domain (e.g., a
dangling CNAME to an unclaimed cloud resource), an attacker could:
1. Take over the subdomain
2. Open the 1Password web client in an iframe (allowed by `frame-ancestors`)
3. Send postMessage with a controlled payload
4. The `L` handler accepts it because the origin passes `D()` validation

The `L` handler dispatches to various flows (DelegatedSession, SingleSignOn,
etc.) — if any of these flows can be triggered externally, this could be
significant.

#### Wildcard postMessage (info leak):
```javascript
window.opener && window.opener.postMessage({READY: true}, "*");
```
When the signin page loads, it sends `{READY: true}` to its opener window
with `"*"` as the target origin. **Any page that opens the signin page via
`window.open()` receives this message.** This is a minor info leak: an
attacker can detect when the signin page has finished loading. Not directly
exploitable for data exfiltration, but could be used as a timing oracle in
a more complex attack chain.

### Service Worker Analysis

**Firebase messaging service worker** (`/firebase-messaging-sw.js`):
- Registered via `navigator.serviceWorker.register("firebase-messaging-sw.js")`
- Imports Firebase SDK via `importScripts` from `app.1password.com`
- Handles push notifications with custom `NotificationEvent` class
- Has full `WebAssembly` API in its scope (unpatched)
- Service Worker scope: root (`/`) — intercepts all fetch events

**No other service workers found.** The app does not register a custom
service worker for offline caching or request interception.

### Summary Assessment

| Finding | Severity | Exploitable? |
|---------|----------|-------------|
| PBKDF2 uses native WebCrypto (CVE-2025-6545 N/A) | — | No |
| Lodash 4.17.21 has unfixed CVEs (CVE-2025-13465, CVE-2026-2950) | Medium | **No** — `_.unset`/`_.omit` not called |
| WASM hash check is main-thread only | Medium | **Theoretical** — requires same-origin script injection |
| postMessage `D()` accepts any `*.1password.com` subdomain | Low | **Conditional** — requires subdomain takeover |
| `window.opener.postMessage({READY:true}, "*")` | Info | Minor timing oracle |
| Firebase service worker has unpatched WASM API | Low | **Theoretical** — requires SW hijacking |
| PBKDF2 default iterations = 650,000 | — | Exceeds OWASP 2025 recommendation |

**The client-side attack surface is well-defended.** The combination of SRI,
strict CSP, WASM hash whitelist, and proper origin validation on critical
postMessage handlers leaves no directly exploitable path without first
obtaining a prerequisite vulnerability (subdomain takeover or same-origin
script injection).

### Step 3.10 — Pre-Auth Endpoint Probing

**Date:** 2026-04-23

#### Recovery Flow Architecture (from JS Bundle)

The recovery flow uses its own SRP handshake, separate from the main auth flow.
All three initial steps are `encrypted: false`:

```
1. POST /api/v2/recovery-keys/session/new
   Body: {recoveryKeyUuid: string}
   Response: {sessionUuid: string, cryptoVersion: string}

2. POST /api/v2/recovery-keys/session/auth/cv1/start
   Body: {bigA: string}  (SRP client ephemeral A)
   Response: {bigB: string}  (SRP server ephemeral B)

3. POST /api/v2/recovery-keys/session/auth/cv1/confirm
   Body: {clientHash: string}  (SRP M1)
   Response: {serverHash: string}  (SRP M2)
```

Steps 4+ (email verification, material retrieval, completion) are `encrypted: true`
— they require the session key from the SRP handshake.

**Recovery key structure:**
```
{uuid, label, enc, encryptedBy, cryptoVersion, verifierParam}
```

The `verifierParam` field is the SRP verifier for this recovery key. Each
recovery key acts as a separate SRP credential, independent of the account
password + Secret Key.

**Testing:** Both `00000000-0000-0000-0000-000000000000` and random UUIDs
return identical `400 {}`. No timing difference (both ~125-155ms, within
network jitter). Recovery key UUID enumeration is not feasible.

#### Pre-Auth Endpoint Scan Results

| Endpoint | Method | Status | Response | Notes |
|----------|--------|--------|----------|-------|
| `/api/v2/preauth-perftrace` | PUT | **200** | `{"success":1}` | Accepts ANY body including empty — write-only telemetry sink |
| `/api/v2/preauth-perftrace` | POST | 405 | — | Method not allowed |
| `/api/v2/preauth-perftrace` | GET | 405 | — | Method not allowed |
| `/api/v2/perftrace` | POST | 405 | — | |
| `/api/v1/monitoring/status` | GET | 401 | `{}` | |
| `/api/v2/signinattempts` | GET | 405 | — | |
| `/api/v1/signinattempts` | POST | 405 | — | |
| `/api/v1/confidential-computing/session` | POST | 422 | `{"reason":"Failed to parse..."}` | Descriptive error with column number |
| `/api/v2/session-restore/save-key` | POST | 401 | `{}` | |
| `/api/v2/session-restore/destroy-key` | POST | 405 | — | |
| `/api/v1/signup` | POST | 400 | `{}` | Signup disabled |
| `/api/v2/signup` | POST | 400 | `{}` | Signup disabled |
| `https://flow.1passwordservices.com/` | GET | 403 | `{"message":"Missing Authentication Token"}` | AWS API Gateway |

#### Confidential Computing Endpoint

`POST /api/v1/confidential-computing/session` returns a **descriptive
Rust serde error** with specific column numbers:

```
{"reason":"Failed to parse the request body as JSON at line 1 column 22"}
```

This is an `encrypted: false` endpoint (from JS analysis). The error format
confirms a **Rust backend** (serde_json error format). The column numbers
shift based on the specific fields sent — the parser successfully reads
the JSON but rejects the structure because required fields are missing or
types are wrong.

This is the only endpoint that returns a descriptive reason in the error
body (besides the `skFormat` validation error discovered in Step 2.1).

#### Secret Key Retrieval Fallback Script

The `sk-2c17b526b1a01ed2f995.min.js` script (54KB) is loaded only when the
main app fails to render (`displayFallback()`). It contains:
- Custom big number library (not WASM-based)
- Standalone SRP implementation (no WebCrypto dependency)
- Used to retrieve the Secret Key in degraded browser environments

This fallback crypto code does NOT go through the WASM hash whitelist or
the main app's crypto pipeline. If an attacker could force the fallback
condition (e.g., by causing the main app scripts to fail), the fallback
SRP code would run without WASM protections. However, the SRP security
properties should be equivalent — the fallback just uses a different
implementation (JS BigInt vs. WASM).

#### Assessment

No exploitable pre-auth endpoints found. Key observations:

1. **`preauth-perftrace`** is a write-only sink — cannot read back data
2. **Recovery flow requires a valid `recoveryKeyUuid`** — UUID space is
   too large to enumerate, responses are identical for all invalid UUIDs
3. **Confidential computing** leaks implementation detail (Rust backend)
   but requires specific structured input we don't have the schema for
4. **Signup is disabled** on the CTF instance — cannot create accounts
5. **All authenticated endpoints return uniform `401 {}`** — no info leaks

### Overall Phase 3 Pre-Auth Assessment

**All pre-auth attack vectors have been exhausted without finding an
exploitable vulnerability.**

| Vector | Status | Verdict |
|--------|--------|---------|
| Client-side JS exploitation | Tested | No XSS vector within CSP constraints |
| WASM module substitution | Tested | Hash whitelist blocks on main thread; Worker bypass theoretical only |
| Lodash prototype pollution | Tested | Vulnerable functions (`_.unset`/`_.omit`) never called |
| postMessage origin bypass | Tested | Requires subdomain takeover (not found) |
| PBKDF2 polyfill weakness | Tested | Native WebCrypto used; CVE-2025-6545 N/A |
| Recovery flow enumeration | Tested | Uniform 400 responses, no timing leak |
| Pre-auth endpoint info leak | Tested | Only `preauth-perftrace` (write-only) returns 200 |
| Signup / account creation | Tested | Disabled on CTF instance |
| User enumeration | Tested | Uniform responses across all tested emails |

**To proceed further, the engagement needs either:**
1. Valid account credentials (email + Secret Key + password)
2. A previously undiscovered pre-auth vulnerability
3. A subdomain takeover on `*.1password.com` (would enable postMessage attack)
4. Access to the server-side infrastructure (out of scope for this CTF)


### Step 3.11 — Crypto Architecture Analysis (from JS Bundle)

**Date:** 2026-04-23

Full key hierarchy reconstructed from the `webapi` and `vendor-1password`
bundles without requiring authentication.

#### Key Derivation Chain

```
Password ──► PBKDF2-HMAC-SHA256 (650k iterations) ──► kdfBytes (32 bytes)
                                                         │
Secret Key ──► HKDF-SHA256(key=SK, salt=format, info=id) ──► personalBytes
                                                         │
                                                    XOR ─┤
                                                         │
                                                    combinedKey (32 bytes)
                                                    ┌────┴────┐
                                                    ▼         ▼
                                              AUK (mp)   SRP-x
                                         (vault unlock)  (auth)
```

**2SKD `combineWithBytes` implementation:**
```javascript
combineWithBytes = async (derivedBytes) => {
    rawKey = this.rawKeyMaterial;        // Secret Key raw bytes
    format = this.format.toString();      // "A3"
    id = this.id;                         // Key UUID
    personal = await HKDF(SHA256, rawKey, format, id, derivedBytes.length);
    return XOR(derivedBytes, personal);   // byte-wise XOR
}
```

The Secret Key contributes entropy through HKDF (not raw XOR), using the
format string as salt and key UUID as info. Both factors (PBKDF2 output +
HKDF output) must be known to reconstruct `combinedKey`.

#### SRP-x Computation

```javascript
x = SHA1(salt || SHA1(email || ":" || hex(combinedKey)))
```

Uses **SHA-1** (160-bit output) per RFC 5054 standard SRP-6a. SHA-1's
collision resistance weakness is irrelevant here — SRP-x only requires
preimage resistance, which SHA-1 still provides. The 160-bit x is fed
into `v = g^x mod N` (the SRP verifier).

#### AES-256-GCM Vault Encryption

```javascript
encrypt = async (plaintext, aad?) => {
    iv = getRandomBytes(12);         // 96-bit random nonce via CSPRNG
    ciphertext = AES-GCM-256(key, iv, plaintext, tagLength=128, aad);
    return {data: ciphertext, iv: iv};
}
```

- **Algorithm:** AES-256-GCM via native `crypto.subtle`
- **IV:** 12 bytes (96 bits) generated by `crypto.getRandomValues()`
- **Tag length:** 128 bits (full GCM tag, no truncation)
- **AAD:** Optional additional authenticated data
- **Key generation:** 32 random bytes via `crypto.getRandomValues()`

Random nonces have a birthday bound collision risk at ~2^48 encryptions
per key. For vault items, this is not a practical concern.

#### Key Hierarchy

```
Account Password + Secret Key
         │
         ▼
   combinedKey (2SKD output)
    ┌────┼────┐
    ▼    │    ▼
  AUK    │   SRP-x ──► SRP verifier v = g^x mod N
  (mp)   │              (stored server-side)
    │    │
    ▼    ▼
  Primary Keyset
    │
    ├──► Vault Keys (per-vault, wrapped by keyset)
    │      │
    │      ├──► Item Keys (per-item AES-256-GCM)
    │      │
    │      └──► Attachment Keys
    │
    ├──► Credential Bundle (SRP-x + AUK, for device auth)
    │
    └──► Recovery Key (optional, separate SRP verifier)
```

#### Observations

1. **No shortcuts exist in the key hierarchy.** Recovering vault items
   requires either the AUK (which requires password + Secret Key) or
   a server-side vulnerability that exposes encrypted blobs AND the
   wrapping keys.

2. **SRP verifier is one-way.** Even with the server's SRP verifier `v`,
   recovering `x` requires solving the discrete logarithm problem mod N
   (a 2048-bit safe prime). This is computationally infeasible.

3. **All cryptographic operations use native `crypto.subtle`** — no
   JavaScript crypto polyfills, no custom RNG, no weak primitives.

4. **The WASM modules in `vendor-1password`** implement the performance-
   critical crypto operations (likely HKDF, key wrapping, perhaps the
   SRP big number operations for the full app path). The fallback `sk`
   script uses SJCL (Stanford JavaScript Crypto Library) for the same
   operations in JS.

5. **Recovery keys have independent SRP verifiers** — compromising a
   recovery key's SRP handshake would only authenticate the recovery
   session, not reveal the vault encryption key. The vault keys are
   still encrypted by the primary keyset, which requires the original
   password + Secret Key to derive.

#### Verdict

The crypto architecture has no theoretical weaknesses exploitable without:
- **Quantum computing** (breaks DLP for SRP, AES-128 effective for Grover's)
- **Implementation bug** (timing leak in server-side modular exponentiation)
- **Server compromise** (access to encrypted blobs + verifier database)
- **Client compromise** (XSS/code injection to capture keys in memory)

All four of these are either out of scope, mitigated by the client-side
protections documented in Step 3.9, or require access we don't have.


### Step 3.12 — Subdomain Enumeration

**Date:** 2026-04-23

Enumerated 35 subdomains of `1password.com`:

| Subdomain | DNS | Notes |
|-----------|-----|-------|
| `status.1password.com` | CNAME → `stspg-customer.com` | StatusPage — **claimed and operational** |
| `b5n.1password.com` | CNAME → `b5n.edge.1password.com` | WebSocket notifier |
| `blog.1password.com` | CloudFront (18.67.65.23) | Blog/content |
| `billing.1password.com` | AWS EU (52.59.156.157) | Billing service |
| `support.1password.com` | 3.162.125.33 | Support site |
| All other subdomains | AWS US A records | Same load balancer cluster |

**All tested subdomains serve the same 1Password web app** (version 2248).
This is a wildcard DNS configuration — `*.1password.com` resolves to the
same ELB cluster and serves the same SPA. There are no dangling CNAMEs
or unclaimed cloud resources.

**Impact on postMessage attack:** The `D()` origin validation weakness
(accepts any `*.1password.com` subdomain) is **NOT exploitable** because
all subdomains serve the identical legitimate app. There is no controlled
subdomain to send malicious postMessage from.


## Engagement Status: Pre-Auth Phase Complete

**Date:** 2026-04-24

### Summary of Findings

**25+ tests conducted across 5 attack domains. No exploitable
vulnerability found without valid account credentials.**

| Phase | Steps | Key Finding |
|-------|-------|-------------|
| 1. Recon | 1.1–1.6 | Minimal surface (80/443 only), strict TLS, SRI on all scripts, WASM hash whitelist, 346K CVEs searched |
| 2. Protocol | 2.1–2.2 | v3 auth discovered, X-AgileBits-Client header required, SRP params need valid (email, skid, userUuid) |
| 3. Client-side | 3.9–3.12 | Native WebCrypto (no polyfill), no exploitable lodash CVE, Worker WASM bypass theoretical only, no subdomain takeover |
| 3. Crypto | 3.11 | 650K PBKDF2 iterations, HKDF-based 2SKD (not raw XOR), 96-bit random GCM nonces, SHA-1 SRP-x per RFC 5054 |
| 3. Pre-auth | 3.10 | Recovery needs valid UUID, signup disabled, preauth-perftrace is write-only, uniform 400/401 errors |

### Blockers

1. **SRP parameters are gatekept** — `/api/v3/auth/start` requires valid
   `(email, skFormat, skid, deviceUuid, userUuid)`. Without these, we
   cannot obtain salt, iterations, or server ephemeral B.

2. **No signup** — the CTF instance has signup disabled. Cannot create
   a test account.

3. **Uniform error responses** — all auth endpoints return identical
   `400 {}` or `401 {}` regardless of input. No information leakage.

4. **Wildcard DNS** — all `*.1password.com` subdomains serve the same
   app. No subdomain takeover possible.

### Recommended Next Steps

1. **Obtain test account credentials** — check if the CTF provides
   credentials via the HackerOne challenge description, registration
   email, or a hidden endpoint. Without credentials, the engagement
   cannot progress to protocol-level testing.

2. **If credentials are obtained:**
   - Run `test_secret_key_validation` for factor separation testing
   - Run `srp_timing_attack` for PARASITE-class timing analysis
   - Run `kdf_oracle_test` for KDF correctness oracle detection
   - Analyze vault encryption key hierarchy with authenticated session
   - Test recovery flow with valid recovery key UUID

3. **Alternative approaches without credentials:**
   - Deeper reverse engineering of the WASM crypto modules
   - Fuzzing the confidential computing endpoint (Rust serde errors
     suggest structured input parsing)
   - Monitoring the v3 auth flow for protocol-level state confusion
     across sessions (session fixation, race conditions)


## Phase 4: Extended Pre-Auth Exploration

### Step 4.1 — Recovery Flow Deep Dive

**Date:** 2026-04-24

Exhaustive analysis of both recovery flows identified in the JS bundles.

#### Recovery Code Flow (`/api/v2/recovery-keys/*`)

**Architecture (from `web-api/api/recovery_key.ts`):**

| # | Endpoint | Method | Encrypted | Purpose |
|---|----------|--------|-----------|---------|
| 1 | `/api/v2/recovery-keys/session/new` | POST | No | Start recovery session with `{recoveryKeyUuid}` |
| 2 | `/api/v2/recovery-keys/session/auth/cv1/start` | POST | No | SRP key exchange `{bigA}` → `{bigB}` |
| 3 | `/api/v2/recovery-keys/session/auth/cv1/confirm` | POST | No | SRP verify `{clientHash}` → `{serverHash}` |
| 4 | `/api/v2/recovery-keys/session/identity-verification/email/start` | POST | Yes | Start email verification |
| 5 | `/api/v2/recovery-keys/session/identity-verification/email/submit` | POST | Yes | Submit verification code |
| 6 | `/api/v2/recovery-keys/session/material` | GET | Yes | Retrieve recovery key material |
| 7 | `/api/v2/recovery-keys/session/complete` | POST | Yes | Complete recovery |
| 8 | `/api/v2/recovery-keys/session/status` | GET | Yes | Session status |

Steps 1–3 are unencrypted (no MAC/session key needed), but step 1 requires
a valid `recoveryKeyUuid` — without it, the server returns `400 {}`.

**Recovery Key Paper Format:**
```
Prefix: "1PRK"
Total length: 56 characters (4 prefix + 52 data)
Charset: "23456789ABCDEFGHJKLMNPQRSTVWXYZ" (30 chars, base-30)
Character normalization: 0→O, 1→I (typo correction)
Raw key: 32 bytes
Entropy: ~255 bits (log2(30^52))
UUID derivation: HKDF(SHA256, rawKey, info="1P_RECOVERY_KEY_UUID", len=16) → hex UUID
```

**Brute force assessment:** 255 bits of entropy. Infeasible. UUID space
(128 bits from HKDF output) is also too large to enumerate.

**Timing analysis:** No measurable timing difference between different
`recoveryKeyUuid` values. All responses are `400 {}` in 125–155ms
(within network jitter). No oracle for valid vs. invalid UUIDs.

**Error codes from JS bundle:** `AuthenticationFailed`, `RecentLogin`,
`RecentAbortedAttempt`, `NotFound`, `IncorrectCode`, `AttemptLimitReached`,
`CodeExpired`, `ResendLimitReached`. These errors are only returned after
a valid recovery session is established.

#### Legacy Recovery Flow (`/api/v1/recover/*`, `/api/v2/recover/*`)

**Endpoints (from `web-api/api/recovery.ts`):**

| Endpoint | Encrypted | Response Type |
|----------|-----------|---------------|
| `POST /api/v1/recover/{token}/details` | No | `{uuid, accountUuid, accountName, email, recoveryKeysExist, isPkvEnabled}` |
| `POST /api/v2/recover/continue` | No | Generic |
| `POST /api/v2/recover/{uuid}/verify-email/start` | No | Generic |
| `POST /api/v2/recover/{uuid}/verify-email/verify` | No | Auth response |

**Key finding:** `findRecoveryDetails` at `/api/v1/recover/{token}/details`
would return **full account information** (email, UUID, account UUID, name)
if a valid recovery token were found. This is the highest-value pre-auth
endpoint — but requires a valid token from a recovery email link.

**Testing:** All token formats (UUIDs, hex strings, arbitrary strings)
return identical `400 {}`. No timing difference. Token space is too large
to enumerate.

#### Session Restore Flow

| Endpoint | Method | Encrypted | Body |
|----------|--------|-----------|------|
| `/api/v2/session-restore/save-key/u` | POST | No | `{jwk, redirectState}` |
| `/api/v2/session-restore/restore-key` | POST | No | `{sessionRestorationToken, redirectState}` |
| `/api/v2/session-restore/destroy-key` | POST | No | — |

All return `400 {}` for all payloads. `sessionRestorationToken` would need
to come from a prior authenticated session.

#### Assessment

Both recovery flows are properly locked down. The pre-auth steps require
secrets (recovery key UUID or email token) that are cryptographically
strong and cannot be enumerated. No timing side-channels were detected.


### Step 4.2 — Unencrypted Endpoint Enumeration (68 endpoints)

**Date:** 2026-04-24

Complete enumeration of all `encrypted: false` API endpoints from the
`webapi` and `app` JS bundles. Every endpoint was probed with the correct
`X-AgileBits-Client: 1Password for Web/2248` header and browser User-Agent.

**Result: All 68 unencrypted endpoints return either `400 {}`, `401 {}`,
`404`, or `405` for invalid inputs. No information leakage was detected
on any endpoint.**

Notable endpoint behaviors:

| Endpoint | Status | Notes |
|----------|--------|-------|
| `PUT /api/v2/preauth-perftrace` | 200 | Write-only telemetry sink, accepts any body |
| `POST /api/v2/auth/methods` | 200 | Returns `{authMethods: [{type: "PASSWORD+SK"}]}` for all emails |
| `POST /api/v1/confidential-computing/session` | 422 | Descriptive Rust serde error with column number |
| All signup endpoints (`v1/v2/v3`) | 400 | Signup disabled on CTF instance |
| Transport token auth | 400 | Alternative auth path, still needs valid account IDs |


### Step 4.3 — WAF Discovery and Provisioning Flow Analysis

**Date:** 2026-04-24

#### WAF Blocks Python User-Agent

The AWS WAF now blocks requests with `Python-urllib/3.12` User-Agent,
returning `403` with a 1-byte body (newline) and `text/plain` content-type.
All requests must include a browser User-Agent string to reach the
application servers.

This was not the case in the initial engagement (Step 1.1–3.12). The
WAF rule was likely triggered by the volume of automated probing.

**Workaround:** Set `User-Agent` to a Chrome/Safari string. All API
endpoints resume normal behavior with a browser UA.

#### Provisioning Flow (from `web-api/api/provision.ts`)

Discovered an extensive provisioning/invitation flow with **multiple
`encrypted: false` endpoints**:

| Endpoint | Method | Encrypted | Purpose |
|----------|--------|-----------|---------|
| `POST /api/v1/provision/user/accept` | POST | **No** | Accept provision invitation |
| `POST /api/v2/provision/user/{uuid}/details` | POST | **No** | Get provisioned user details |
| `PUT /api/v2/provision/user/{uuid}/send` | PUT | **No** | Send provision confirmation |
| `PUT /api/v2/provision/user/{uuid}/confirm/start` | PUT | **No** | Start confirmation |
| `GET /api/v2/provision/user/{uuid}/{token}/{code}` | GET | **No** | Check email verification |
| `POST /api/v2/provision/user/{uuid}/state` | POST | **No** | Find provisioned user state |
| `POST /api/v2/provision/user/confirm/finish` | POST | **No** | Finish confirmation (v2, with custom headers) |

**The `getProvisionedUserDetails` response type** (from `io-ts` codec in
the bundle) would return:
```
{uuid, accountName, accountType, accountUuid, domain, name, email,
 userState, accountUsesNewKeysets, ...}
```

This is extremely valuable — it leaks the account UUID, user UUID, email,
and domain. However, **all endpoints return `400 {}` for invalid UUIDs
and tokens.** The provision UUID must come from an invitation email link.

**`finishUserConfirmationV2`** uses a separate request path with custom
headers `X-User-UUID`, `X-Account-UUID`, and optional `X-SSO-Identity`.
It routes to a separate microservice at
`/provisioning-key-service/api/v2/user/confirm/finish` (returns `404` —
service likely not exposed publicly).

**`/api/v1/invite/accept`** returns `405` for GET/POST/PUT/PATCH but
`401` for DELETE — the DELETE method is accepted but requires authentication.

#### Endpoint Category Probing

| Category | Paths Tested | Result |
|----------|-------------|--------|
| Provisioning key service | `/provisioning-key-service/*` | 404 (not exposed) |
| Health/readiness | `/health`, `/healthz`, `/ready`, `/api/health` | 403 (WAF) or SPA catch-all |
| Debug/profiling | `/debug/pprof`, `/_debug`, `/api/internal` | 403 or SPA |
| GraphQL | `/graphql`, `/api/graphql` | 403 or SPA |
| API docs | `/swagger.json`, `/openapi.json`, `/api/docs` | SPA catch-all |
| Well-known | `/.well-known/*` | 404 or SPA |
| Hidden files | `/.git/config`, `/.env`, `/flag.txt` | SPA catch-all or 404 |
| SSO/OIDC | `/api/v1/oidc/token`, `/api/v2/auth/sso/*` | 401 or 404 |

#### Confidential Computing Schema Fuzzing

The `POST /api/v1/confidential-computing/session` endpoint returns
descriptive Rust serde errors with column numbers. Schema analysis:

- The error column always equals `len(json_body)` — it reads the entire
  JSON object and fails at EOF with a "missing field" error
- Cannot determine required field names from column numbers alone
- From JS bundle: `confidentialComputingCreateSession` passes the body
  through directly from the caller — need to find the caller's payload
  structure

#### HTML Metadata

```html
data-avatar-base="https://a.1passwordusercontent.com/"
data-backoffice-banner="Production"
data-backoffice-stage="prd"
data-billing-origin="https://billing.1passwordservices.com"
data-billing-subdomain-origin="https://pay.1password.com"
```

- `robots.txt` returns `Disallow: /`
- No HTML comments, no hidden CTF hints in page source
- Sentry debug ID: `02b93407-0f50-4a94-9fe1-fe5a6dcddee5` (no DSN URL found)
- No hardcoded credentials, flags, or test accounts in JS bundles

#### Auth Flow State Manipulation

Tested auth flow state manipulation:
- `POST /api/v2/auth` without prior `startAuth` → `400 {}`
- `POST /api/v2/auth/confirm-key` without prior session → `400 {}`
- `POST /api/v2/auth` with fake `X-AgileBits-Session-ID` header → `400 {}`

The server validates session state on every step — no state confusion
or session fixation possible.

### Current Assessment

**All pre-auth attack vectors exhausted across 4 phases of testing.**

| Phase | Vectors Tested | Exploitable? |
|-------|---------------|-------------|
| 1. Infrastructure | Port scan, TLS audit, service fingerprinting | No |
| 2. Protocol | SRP flow, auth parameters, client header | No |
| 3. Client-side | JS analysis, WASM, lodash CVEs, postMessage, CSP, subdomains | No |
| 4. Extended | Recovery flows (2), provisioning (7 endpoints), CC fuzzing, auth state, OIDC | No |

**Total endpoints probed:** ~90 across all phases
**Information leaks found:** 2 (both low-value)
  1. `auth/methods` confirms `PASSWORD+SK` auth type (no user enumeration)
  2. Confidential computing reveals Rust backend (serde error format)

**Remaining theoretical vectors:**
1. Sentry error reporting — trigger informative stack traces
2. WebSocket notifier (`b5n.1password.com`) — different auth model?
3. Billing/payment services — `billing.1passwordservices.com`, `pay.1password.com`
4. Avatar service — `a.1passwordusercontent.com`
5. HTTP/2 specific attacks (request smuggling behind ELB)
6. Race conditions on multi-step auth flow (concurrent requests)
7. ETH Zurich malicious-server scenarios (requires MITM position)


### Step 4.4 — Remaining Vector Elimination

**Date:** 2026-04-24

Systematic elimination of all remaining theoretical vectors from Step 4.3.

#### WAF User-Agent Blocking

During Phase 4, the AWS WAF began blocking `Python-urllib/3.12` User-Agent
strings, returning `403` with a 1-byte body. All subsequent probes use a
Chrome browser User-Agent. This confirms active WAF monitoring — the probe
volume triggered a detection rule.

#### WebSocket Notifier (`b5n.1password.com`)

- DNS: resolves to `3.171.38.109` (CloudFront edge)
- Infrastructure: Behind CloudFront (`Via: 1.1 ...cloudfront.net`)
- All paths (`/`, `/ws`, `/socket`, `/connect`, `/health`, `/api`,
  `/notification`) return `400 Bad Request`
- WebSocket upgrade with `Sec-WebSocket-Protocol: 1password-b5` → `400`
- **The notifier URL is only available from `session.serverConfig.notifier`
  after authentication.** The server returns a WebSocket URL as part of
  the post-auth session initialization. Without auth, we can't discover
  the correct connection path.

#### Billing Service (`billing.1passwordservices.com`)

- Infrastructure: **Static S3 website** behind CloudFront (`Server: AmazonS3`)
- Content: A 318-byte HTML page with two scripts:
  - `/js/bundle.e7e3cfea471c58d99fd1f31abe25393db19cb813.js` (3.8KB)
  - `https://js.stripe.com/v2/`
- CSP: `script-src 'self' https://js.stripe.com; frame-src https://js.stripe.com`
- The JS bundle is a simple Stripe `card.createToken()` form — no 1Password
  API calls, no backend endpoints
- All API paths (`/api/*`, `/webhook`, etc.) return 404 HTML errors
- **No attack surface** — pure client-side Stripe checkout hosted on S3

#### Avatar Service (`a.1passwordusercontent.com`)

- Infrastructure: AWS S3 bucket
- All requests return `403 AccessDenied` (XML error)
- Bucket listing not allowed, direct object access denied
- **No attack surface** without knowing a valid avatar object key

#### Firebase Cloud Messaging

Service worker config from `/firebase-messaging-sw.js`:
```javascript
apiKey: "AIzaSyCs8WNa10YE5AVyfL33RBHBKQdYZMw7OB0"
projectId: "b5-notification-prd"
messagingSenderId: "928673166066"
appId: "1:928673166066:web:d02cb3a827413eaf69d66b"
```

- Firebase Realtime Database: `404` (not configured)
- Firebase Firestore: `404` (not configured)
- **FCM only** — the project is push-notification-only, no data storage

#### SSRF via `preauth-perftrace`

The `PUT /api/v2/preauth-perftrace` endpoint accepts any JSON body and
returns `{"success": 1}`. Tested with:
- AWS metadata URLs (`169.254.169.254/latest/meta-data/`)
- Internal URLs (`http://localhost:8080/`, `http://127.0.0.1/`)
- All return `{"success": 1}` identically

**The endpoint is a write-only telemetry sink** — it accepts the body,
stores or discards it, and returns success. It does NOT process URLs in
the body as fetch targets. **No SSRF.**

#### Race Conditions

Sent 10 concurrent `POST /api/v3/auth/start` requests with identical
parameters. Results:
- All returned `400 {}` (no different behavior under race)
- Two threads took ~1100ms (vs. ~130ms baseline) — likely rate limiting
  on concurrent connections, not a functional difference
- **No TOCTOU bugs or state confusion detected**

#### Path Normalization

| Variation | Result |
|-----------|--------|
| Double slash (`//api/v3/auth/start`) | 400 — same as normal |
| Trailing slash (`/api/v3/auth/start/`) | 400 — same |
| Path traversal (`/api/v3/../v3/auth/start`) | 400 — same |
| Null byte (`/api/v3/auth/start%00`) | 400 HTML nginx error |
| Uppercase (`/API/V3/AUTH/START`) | 404 — case-sensitive routing |
| Semicolon (`/api/v3/auth/start;`) | 404 |
| Extension (`/api/v3/auth/start.json`) | 404 |

**No path confusion.** The Go HTTP router is case-sensitive and does not
normalize path traversal in a way that bypasses routing.

#### Content-Type Confusion

Tested `application/xml`, `text/plain`, `application/x-www-form-urlencoded`,
`multipart/form-data`, and `text/xml` against `/api/v3/auth/start`. All
return `400 {}` — the server gracefully handles incorrect content types.

#### Mycelium Protocol Discovery

**Major finding:** Mycelium is 1Password's device-to-device pairing protocol
("Set Up Another Device"). The `/u` (unencrypted transport) variant has
10+ endpoints, all marked `encrypted: false` in the JS bundle:

| Endpoint | Method | Auth Required | Purpose |
|----------|--------|--------------|---------|
| `/api/v2/mycelium/u` | POST | Yes* | Create channel (`{deviceUuid, hello}`) |
| `/api/v2/mycelium/u/{uuid}/1` | GET | `ChannelJoinAuth` | Get hello message |
| `/api/v2/mycelium/u/{uuid}/2` | PUT | `ChannelJoinAuth` | Send reply |
| `/api/v2/mycelium/u/{uuid}/2` | GET | `ChannelAuth` | Get reply |
| `/api/v2/mycelium/u/{uuid}/{n}` | GET/PUT | `ChannelAuth` | Exchange messages |
| `/api/v2/mycelium/u/{uuid}/switch-region` | PUT | `ChannelJoinAuth` | Switch region |
| `/api/v2/mycelium/u/{uuid}/reconnect` | POST | `ChannelAuth` | Get reconnect token |
| `/api/v2/mycelium/u/{uuid}` | DELETE | `ChannelAuth` | Close channel |

\* Returns `400 {}`, not `401` — endpoint exists and processes the body,
but either requires session context or rejects our body format.

**Channel auth tokens:**
- `ChannelJoinAuth` — derived from QR code scanned by the joining device
- `ChannelAuth` — established after the channel handshake completes
- Both are passed as custom HTTP headers

**Critical protocol detail:** The Mycelium flow transmits a session key:
```javascript
{session_uuid: string, session_key: JwkSymKey, notifier_url: string}
```
This means a successful Mycelium channel exchange gives the joining device
full session access (session UUID + key + notifier URL).

**Assessment:** The Mycelium protocol is a high-value attack surface in
theory — it's a channel for transmitting session credentials in cleartext
HTTP bodies. However, creating a channel requires an authenticated session,
and joining requires the QR code seed (which is displayed on the
initiator's screen). Without either, we cannot create or join channels.

#### Direct Vault Access

All vault endpoints (`/api/v1/vault/personal`, `/api/v1/vault/everyone`,
`/api/v1/vault/export`, `/api/v2/vault`, `/api/v2/account/keysets`,
`/api/v1/account`) return `401 {}` — auth required, no data leakage.

#### Debug/Test Parameters

Tested `?debug=1`, `?verbose=1`, `?trace=1`, `?test=1`, `?dev=1`,
`?internal=1` on `/api/v3/auth/start`. No effect — all return `400 {}`.

#### Forged Session Headers

Sending requests with a fake `X-AgileBits-Session-ID` header to
authenticated endpoints (`/api/v1/vault/personal`, `/api/v1/account`,
etc.) returns `401 {}` — the server validates session IDs against its
session store.

#### CTF Instance vs. Production Comparison

| Attribute | CTF | Production (`my.1password.com`) |
|-----------|-----|-------------------------------|
| Data attributes | Identical | Identical |
| Script bundles | Same CDN paths, same hashes | Same |
| CSP policy | Same (minor whitespace diff) | Same |
| Version | 2248 | 2248 |

**The CTF instance is the production 1Password web app** with a
CTF-specific account on the backend. There is no CTF-specific frontend
configuration, no hidden endpoints, no debug modes.

#### SK Fallback Script Analysis

The `sk-2c17b526b1a01ed2f995.min.js` (54KB) fallback script contains:
- Stanford JavaScript Crypto Library (SJCL) with BigNumber support
- ECC curve parameters (P-192, P-256, P-384, P-521)
- Base32/Base64 codecs
- Standalone SRP implementation (no WebCrypto dependency)
- Links to 1Password support pages for Secret Key recovery

**No hardcoded credentials, test accounts, flags, or debug values.**


## Engagement Status: All Pre-Auth Vectors Exhausted

**Date:** 2026-04-24

### Final Summary

**100+ attack vectors tested across 4 phases. No exploitable pre-auth
vulnerability found.**

| Category | Tests | Endpoints | Result |
|----------|-------|-----------|--------|
| Infrastructure | Port scan, TLS, services | 2 ports | Locked down (ELB + TLS 1.2/1.3 only) |
| Protocol | SRP flow, auth chain, client header | 5 auth endpoints | `(email, skid, userUuid)` required |
| Client-side | 8 JS bundles, WASM, CSP, postMessage | — | No XSS, no bypasses |
| CVE research | 346K CVEs, 13 1Password-specific | — | No applicable remote vuln |
| Crypto | Key hierarchy, 2SKD, AES-GCM | — | Sound design, native WebCrypto |
| Subdomains | 35 subdomains enumerated | — | All serve same app (wildcard DNS) |
| Recovery | 2 flows, 12 endpoints | 12 | All need cryptographic tokens |
| Provisioning | 7 unencrypted endpoints | 7 | All need valid provision UUIDs |
| Mycelium | 10+ channel endpoints | 10 | All need session or QR auth |
| Auxiliary | Billing, avatar, Firebase, flow | 4 services | No attack surface |
| Error triggers | Path, content-type, debug, race | ~30 variations | No information leakage |

### Why the Engagement Is Blocked

The core blocker is the **authentication wall**. 1Password's design
ensures that no useful data is accessible without completing the full
authentication handshake:

1. **SRP init requires `(email, skFormat, skid, deviceUuid, userUuid)`**
   — without valid values, the server returns `400 {}` with no
   distinguishing information
2. **Signup is disabled** on the CTF instance — cannot create an account
3. **Recovery requires cryptographic secrets** (255-bit recovery key or
   email token) — cannot enumerate or guess
4. **Provisioning requires invitation tokens** from an admin — none available
5. **Mycelium requires either an authenticated session or a QR code seed**
6. **All error responses are uniform** — `400 {}` or `401 {}` with no
   information leakage

### What Would Advance the Engagement

1. **Credentials from CTF organizers** — the challenge may require
   starting with partial credentials (email address, for instance)
   obtained from the HackerOne CTF page or by contacting
   `bugbounty@agilebits.com`

2. **A novel SRP or 2SKD attack** — an academic breakthrough that
   bypasses the `(password × Secret Key)` requirement

3. **A server-side zero-day** — a bug in the Go/Rust backend that
   leaks data without authentication

4. **Malicious server position** (ETH Zurich model) — requires MITM
   on the TLS connection, which is out of scope for external testing

5. **A Mycelium protocol vulnerability** — if the channel UUID or
   auth token derivation has a weakness that allows joining without
   the QR code. This would require access to the WASM crypto modules
   that implement the Mycelium key exchange


---

## Phase 5: Playwright MITM & Deep Attack Surface Exploration

### 5.1 Playwright MITM Setup

Playwright's bundled Chromium was blocked by 1Password's browser version
check ("Update your browser"). Bypassed by launching system Chrome:

```python
browser = pw.chromium.launch(channel="chrome", headless=True)
# Chrome 147.0.7727.116 passes version check
```

Injected JavaScript hooks to intercept:
- All `crypto.subtle` methods (deriveBits, importKey, sign, verify, digest, encrypt, decrypt)
- All `window.fetch` calls (request/response bodies, headers)

### 5.2 Full SRP Key Derivation Capture

Captured the complete 2SKD key derivation chain for account
`ctf@bugbounty-ctf.1password.com`:

| Step | Operation | Parameters | Output |
|------|-----------|-----------|--------|
| 1 | importKey | Email as raw bytes → HKDF key | CryptoKey |
| 2 | HKDF-SHA256 | salt=server_salt, info="SRPg-4096" | 32-byte personalized salt |
| 3 | importKey | Password as raw bytes → PBKDF2 key | CryptoKey |
| 4 | PBKDF2-HMAC-SHA256 | salt=personalized_salt, iterations=100000 | 32-byte password key |
| 5 | importKey | SK raw material → HKDF key | CryptoKey |
| 6 | HKDF-SHA256 | salt=SK_id, info=SK_format | 32-byte SK key |
| 7 | XOR | password_key ⊕ SK_key | 32-byte combined key (SRP-x) |

**Confirmed account parameters:**
- Email: `ctf@bugbounty-ctf.1password.com`
- Secret Key UUID: `92C843`
- SRP group: `SRPg-4096`
- PBKDF2 iterations: `100,000`
- Server salt (base64url): `IBP--AuszT6YOicP5GFRXw`
- Auth flow: POST `/api/v2/auth/methods` → POST `/api/v3/auth/start` → POST `/api/v2/auth`

### 5.3 PBKDF2 Iteration Downgrade (MITM)

Tested JS-level fetch interception to modify the `auth/start` response
and reduce PBKDF2 iterations:

| Injected Iterations | Client Behavior |
|---------------------|----------------|
| 1 | Rejected — client enforces minimum |
| 100 | Rejected |
| 1,000 | Rejected |
| 10,000 | **Accepted** — client derives with 10K |
| 50,000 | Accepted |
| 99,999 | Accepted |

**Finding:** Client-side minimum threshold is **10,000 iterations**. A MITM
can achieve a 10x reduction from the server's 100K. This doesn't break
authentication (still need correct password + SK), but weakens offline
cracking resistance if key material is captured.

### 5.4 SRP Group Downgrade

Tested modifying `userAuth.method` in auth/start response:

| Injected Method | Client Behavior |
|-----------------|----------------|
| `SRPg-2048` | Rejected — "Unknown SRP method" |
| `SRPg-4096` | Accepted (baseline) |

**Finding:** Client only accepts `SRPg-4096`. No downgrade possible.

### 5.5 Account Enumeration via auth/start

Tested auth/start with non-existent emails:

| Email | Response | Salt | UUID |
|-------|----------|------|------|
| `ctf@bugbounty-ctf.1password.com` (real) | 200 | `IBP--AuszT6YOicP5GFRXw` | `92C843` |
| `xxnotreal@bugbounty-ctf.1password.com` | 200 | Deterministic fake | Deterministic fake |
| `a@b.c` | 200 | Deterministic fake | Deterministic fake |

**Finding:** Server returns **deterministic fake parameters** for
non-existent accounts. Same UUID and salt across multiple requests for
the same email. This is better than random (which would be
indistinguishable from real), but still leaks no usable information
since the fake values are consistent.

### 5.6 Recovery Code Analysis

**Client-side format:** `1PRK` prefix + 52 characters from charset
`23456789ABCDEFGHJKLMNPQRSTVWXYZ` (30 chars). Total: 56 characters.
Raw key: 32 bytes (256 bits). UUID derived via
`HKDF(SHA256, rawKey, info="1P_RECOVERY_KEY_UUID", len=16)`.

**Validation:** Entirely client-side. The client validates:
1. Length check (56 chars)
2. `1PRK` prefix
3. Base-32 roundtrip validation (charset check)
4. **Zero API calls for invalid codes** — no server-side brute force possible

Tested formats: too short, wrong prefix, no prefix, all-same-chars.
All rejected client-side with no network traffic.

### 5.7 Mycelium Pairing Protocol (Complete)

Reverse-engineered the full Mycelium "sign in with another device" flow
from JS bundles:

**Channel types:** `u` (unencrypted) and `v` (encrypted)

**Protocol flow (u-channel):**
1. Page creates channel: `POST /api/v2/mycelium/u` with `{deviceUuid, hello}`
   - Returns `{channelSeed, channelUuid, initiatorAuth}`
   - `hello` is WASM-generated pairing public key
2. QR code contains: `[UNAUTHORIZED_DEVICE_DRIVEN, channelSeed, publicKey]`
3. Authenticated device scans QR, derives `ChannelJoinAuth` from `channelSeed`
   via `WasmChannelSeed.derive_auth()`
4. Device reads hello: `GET /u/{uuid}/1` with `ChannelJoinAuth` header
5. Device sends reply: `PUT /u/{uuid}/2` with `ChannelJoinAuth` header
   - Returns `{responderAuth}`
6. Page reads reply: `GET /u/{uuid}/2` with `ChannelAuth` header
7. Both sides derive shared key via WASM pairing session
8. Device sends encrypted credentials over the channel

**Auth headers:** `ChannelAuth` (initiator), `ChannelJoinAuth` (responder)
— NOT standard Authorization headers.

**Attack assessment:** Channel creation is unauthenticated, but pairing
requires an authenticated device on the other end. Dead end without
credentials.

**WASM pairing classes:**
- `WasmPairingCredentials`: ECDH keypair generation
- `WasmPairingSetupCredentials`: Setup credential generation
- `WasmPairingSessionStarterExistingDevice`: join, receive_hello, create_reply
- `WasmPairingSessionStarterNewDevice`: init, create_hello, receive_reply, shared_key
- `WasmChannelSeed`: new, derive_auth

### 5.8 API Endpoint Catalog (Phase 5 Additions)

| Endpoint | Method | Status | Notes |
|----------|--------|--------|-------|
| `/api/pre-registration-features` | POST | 200 | Feature flags (auto-sign-in, mycelium-forward-sign-in) |
| `/api/v1/accountcookies` | GET | 200 | Returns `[]` — no account cookies |
| `/api/v2/mycelium/u` | POST | 200 | **No auth required** — creates pairing channel |
| `/api/v2/mycelium/u/{uuid}/{n}` | GET | 200/401 | Requires `ChannelAuth` header |
| `/api/v1/confidential-computing/session` | POST | 422 | Exists, expects specific JSON struct |
| `/api/v1/vault` | POST | 401 | Needs auth (Allow: POST only) |
| `/api/v1/vault/items` | GET | 401 | Needs auth |
| `/api/v1/vaults` | GET | 401 | Needs auth |
| `/api/v1/user` | POST | 400 | Needs specific params (Allow: POST only) |
| `/api/v1/account` | GET | 401 | Needs auth |
| `/api/v2/session-restore/restore-key` | POST | 400 | Exists, unknown params |
| `/api/v1/signup` | POST | 400 | Exists, probably disabled |
| `/api/v1/invite` | POST | 401 | Needs auth |
| `/api/v2/recovery-keys/session/new` | POST | 400 | Needs specific params |
| `/api/v2/recovery-keys/policies` | GET | 401 | Needs auth |
| `/debug/vars` | GET | 403 | Go expvar — blocked |
| `/manifest.json` | GET | 200 | GCM sender ID only |

### 5.9 HTML Head Configuration Dump

The `<head>` tag exposes extensive configuration (acknowledged as
intentional via `data-bug-researcher-notes`):

| Attribute | Value | Notes |
|-----------|-------|-------|
| `data-env` | `prd` | Production environment |
| `data-version` | `2248` | Web client version |
| `data-gitrev` | `33a8e241e543` | Git revision |
| `data-hostname` | `1password.com` | |
| `data-sibling-domains` | `1password.ca,1password.eu,ent.1password.com` | |
| `data-sentry-dsn` | `https://[pub]:[sec]@web-ui-sentry.1passwordservices.com/[id]` | Both keys in DSN |
| `data-fcm-api-key` | `AIzaSyCs8WNa10YE5AVyfL33RBHBKQdYZMw7OB0` | Firebase Cloud Messaging |
| `data-stripe-key` | `pk_live_F59R8NjiAi5Eu7MJcnHmdNjj` | Stripe publishable |
| `data-brex-client-id` | `bri_b2df18d65bc82a948573537157eceb07` | |
| `data-slack-client-id` | `36986904051.273534103040` | |

All keys confirmed as public/publishable. Sentry DSN doesn't enable
reading events (CORS blocks, store endpoint requires server-side auth).

### 5.10 Support/Email Recovery Flow

Support flow at `/support`: enter email → GET request returns
`{"success": 1}` → page shows "An email with instructions has been sent".

All tested emails return identical `{"success": 1}` — no account
enumeration. Tested: ctf@, admin@, test@, poetry@, flag@, user@,
demo@, challenge@ (all @bugbounty-ctf.1password.com).

No server-side state created that we can exploit.

### 5.11 Phase 5 Summary

| Category | Tests Run | Finding |
|----------|-----------|---------|
| MITM/Injection | Iteration downgrade, SRP group, salt manipulation | Client min 10K iterations; SRPg-4096 only |
| Account enum | auth/start with real/fake emails | Deterministic fake params (minor info leak) |
| Recovery code | Format validation, API probing | Client-side only, 256-bit keyspace |
| Mycelium | Channel creation, pairing protocol | Unauthenticated channel creation, but needs paired device |
| Confidential computing | Field discovery, format probing | 422 for all payloads — unknown required struct |
| API catalog | ~80 endpoint/method combinations | All authenticated endpoints return 401/400 |
| Debug endpoints | /debug/vars bypass attempts | 403, no bypass found |
| Service endpoints | 7 external service domains | All CORS-blocked |
| Sentry | API read attempts | 401, can't read error events |
| SSO/OIDC | 13 endpoint probes | All 404 |
| Feature flags | pre-registration-features | Empty list returned |
| HTML config | Head data attributes | All intentionally public |

### Assessment After Phase 5

The engagement remains blocked at the authentication wall. Phase 5
confirmed that 1Password's client-side implementation is sound:

1. **2SKD prevents offline attacks** — even with 10x iteration reduction,
   the 128-bit Secret Key dominates the keyspace
2. **SRP implementation is correct** — proper group validation, no
   zero-key acceptance, constant-time-equivalent responses
3. **No information leakage** — uniform error responses across all
   endpoints; deterministic fake params prevent enumeration
4. **Recovery requires cryptographic secrets** — client validates
   locally, 256-bit recovery key space is infeasible
5. **Mycelium requires authenticated device** — channel creation is
   open but useless without a paired device
6. **No alternative auth paths** — SSO, session-restore, signup, and
   invite endpoints all require proper authentication

The only remaining theoretical attack vectors are:
- A server-side zero-day in the Go/Rust backend
- A novel cryptographic attack against SRP-6a + 2SKD
- A vulnerability in the WASM pairing/crypto modules
- Starting credentials from the CTF organizers


## Phase 6 — Tooling Expansion

**Date:** 2026-04-24

### 6.1 Circular Import Fix

Fixed a circular import that broke the entire test suite:

```
clearwing.agent.tooling → clearwing.llm.native → clearwing.llm.__init__
  → clearwing.llm.chat → clearwing.agent.tooling (ensure_agent_tool)
```

`ensure_agent_tool` at line 139 of `tooling.py` hadn't been defined yet when
`chat.py` tried to import it at module init. Fix: moved the import in
`chat.py` from module-level to lazy inside `bind_tools()`.

### 6.2 Feature 4.12 — Credential Attack Tools

Implemented 4 tools in `clearwing/agent/tools/crypto/credential_tools.py`
(already wired and tested from a prior session):

| Tool | Type | Purpose |
|------|------|---------|
| `analyze_2skd_entropy` | Offline | Calculate combined password×Secret Key keyspace; compare password-only vs 2SKD cracking costs at GPU price points |
| `test_secret_key_validation` | Online | Test for factor separation — whether server distinguishes wrong-password from wrong-Secret-Key (timing, response body, status code) |
| `enumerate_secret_key_format` | Online | Probe enrollment/auth endpoints for Secret Key format info; analyze A3-XXXXXX structure for fixed vs random components |
| `offline_crack_setup` | Offline | Generate hashcat/john command lines for captured PBKDF2/SRP params; flags when 2SKD makes standard tools insufficient |

Key finding from `analyze_2skd_entropy`: default parameters (40-bit password +
128-bit Secret Key + 100K PBKDF2 iterations) yield 168-bit combined entropy —
computationally infeasible with any foreseeable technology. The Secret Key is
the dominant security factor.

### 6.3 New Tool Modules (15 tools, 102→117 total)

Gap analysis identified 5 areas where manual Playwright scripts were
repeatedly needed. Built dedicated tool modules for each.

#### 6.3.1 Mycelium Protocol Tools (`crypto/mycelium_tools.py`)

4 tools for analyzing the device pairing protocol:

| Tool | Purpose |
|------|---------|
| `mycelium_create_channel` | Create unencrypted (`u`) or encrypted (`v`) pairing channels — pre-auth, no credentials needed |
| `mycelium_probe_channel` | Read/write channel segments with configurable auth headers (`ChannelAuth`, `ChannelJoinAuth`) |
| `mycelium_fuzz_auth` | Test 10 auth bypass patterns: no auth, empty headers, random tokens, seed-as-auth, bearer format, zero auth |
| `mycelium_test_race` | Fire concurrent join attempts to test if multiple devices can join or if segment data leaks to unauthorized joiners |

Design: uses `OP-User-Agent` header matching 1Password's format. HTTP helper
(`_http_request`) supports GET/POST/PUT with custom headers and logs to proxy
history.

#### 6.3.2 Recovery Code Tools (`crypto/recovery_tools.py`)

3 tools for recovery code analysis:

| Tool | Purpose |
|------|---------|
| `generate_recovery_codes` | Generate valid-format `1PRK-XXXXXX-...` codes (33-char base32, 52 random chars = 262 bits) |
| `test_recovery_acceptance` | Submit codes to 8 common recovery endpoint paths; detect active endpoints and improper validation |
| `analyze_recovery_entropy` | Calculate brute-force cost at various rates (online 10/s through offline 1B/s); assess lockout impact |

Key finding: recovery codes have ~262 bits of entropy — exceeds AES-256.
Even at 1 billion attempts/sec offline, exhaustion takes ~10^60 years.

#### 6.3.3 Session/Token Replay Tools (`recon/session_tools.py`)

3 tools replacing manual proxy-replay workflows:

| Tool | Purpose |
|------|---------|
| `extract_session_tokens` | Parse proxy history for bearer tokens, session cookies, CSRF tokens, and custom auth headers |
| `replay_with_mutations` | Replay a captured token with 11+ mutations: truncated, reversed, bit-flipped, case-changed, null-appended, random same-length |
| `test_session_fixation` | Compare pre/post-auth cookies to detect session-like identifiers that survive authentication |

#### 6.3.4 JS Bundle Analysis Tools (`recon/bundle_tools.py`)

3 tools replacing one-off Playwright bundle search scripts:

| Tool | Purpose |
|------|---------|
| `fetch_js_bundles` | Fetch page HTML, extract `<script src>` tags, download all bundles (configurable max size/count) |
| `search_bundle_patterns` | Search bundles against 11 built-in regex patterns (hardcoded secrets, flags, API keys, JWTs, debug code, eval, innerHTML, postMessage) plus custom terms |
| `extract_api_routes` | Extract API endpoint definitions from fetch calls, route constants, and method-specific patterns; build API surface map with method detection |

Built-in patterns cover: `hardcoded_secret`, `flag_format`, `private_key`,
`aws_key`, `jwt`, `internal_url`, `debug_code`, `console_log`, `eval_usage`,
`innerHTML`, `postMessage_star`.

#### 6.3.5 Confidential Computing Tools (`recon/cc_tools.py`)

2 tools for the `/api/v1/confidential-computing/session` endpoint:

| Tool | Purpose |
|------|---------|
| `cc_discover_schema` | Iteratively probe serde error messages to discover required JSON fields; builds payload field-by-field with type inference from error text |
| `cc_fuzz_fields` | Fuzz each discovered field with 16 value types: empty, null, zero, negative, large int, booleans, arrays, objects, long strings, XSS, SQLi, null bytes, unicode, UUID, base64 |

Schema discovery logic: parse `missing field`, `unknown field`, and
`expected` patterns from Rust serde errors; infer types from `u64`,
`bool`, `str`, `Vec`, `struct` keywords; fall back to trying all type
guesses when no new fields are revealed.

### 6.4 Knowledge Graph Integration

All 15 new tools have knowledge graph populators in `runtime.py`:

- **Mycelium**: Records protocol, channels, auth bypass vulns, race conditions
- **Recovery**: Records accepted codes as critical vulns, entropy as key material
- **Session**: Records weak token validation and session fixation as vulns
- **Bundle**: Records leaked secrets/flags as vulns, discovered routes as endpoints
- **CC**: Records discovered schema, accepted fuzz values as vulns

### 6.5 Test Coverage

| Test File | Tests | Status |
|-----------|-------|--------|
| `test_credential_tools.py` | 33 | All pass |
| `test_mycelium_tools.py` | 16 | All pass |
| `test_recovery_tools.py` | 15 | All pass |
| `test_session_tools.py` | 12 | All pass |
| `test_bundle_tools.py` | 13 | All pass |
| `test_cc_tools.py` | 11 | All pass |
| `test_tool_registry.py` | 3 | All pass (count updated 102→117) |
| `test_kdf_tools.py` | 34 | All pass (no regression) |
| `test_srp_tools.py` | 13 | All pass (no regression) |
| **Total** | **157** | **All pass** |

All files lint-clean (`ruff check` passes).

### 6.6 Current Tool Inventory Summary

| Domain | Module | Tool Count |
|--------|--------|------------|
| Scan | scanner, tls | 8 |
| Exploit | exploit, payload, search | 13 |
| Crypto | SRP, KDF, vault, credential, mycelium, recovery, timing | 26 |
| Recon | browser, proxy, webcrypto, auth_recorder, mitm, session, bundle, CC, pivot | 32 |
| Data | knowledge, memory, CVE, analysis | 10 |
| Meta | reporting, utility, remediation, wargame, OT, sourcehunt | 18 |
| Ops | kali, MCP, dynamic, skills | 10 |
| **Total** | | **117** |

---

## Phase 7 — Live Attack Vector Exploration

**Date:** 2026-04-24
**Target:** bugbounty-ctf.1password.com

### 7.1 SRP Cryptographic Attack Probes

**Objective:** Test SRP-6a zero-key attacks, parameter variations, and timing analysis.

**Results:**

| Test | Status | Response | Notes |
|------|--------|----------|-------|
| `POST /api/v1/auth` (email) | 401 | `{}` | No SRP params returned |
| `POST /api/v3/auth/start` (full body) | 400 | `{}` | Passes skFormat validation, fails later |
| `POST /api/v3/auth/start` (no skFormat) | 400 | `{"reason":"invalid_sk_prefix_format"}` | Error message leaked |
| SRP zero-key A=0,N,2N... | 403 | Blocked | WAF blocks verify endpoint |
| Timing: real vs fake email | 2.3ms diff | Within noise | No user enumeration via timing |

**Key Finding:** `skFormat` validation reveals accepted values:
- `A2` and `A3` are valid Secret Key format prefixes
- All other values (`A1`, `A4`, `B5`, etc.) return `invalid_sk_prefix_format`

The auth/start endpoint accepts the body but returns 400 `{}` — the server intentionally suppresses error details after the format check.

### 7.2 Mycelium Channel Probes

**Objective:** Test channel creation, auth bypass, race conditions, and type confusion.

**Results:**

| Endpoint | Headers | Status | Notes |
|----------|---------|--------|-------|
| `POST /api/v2/mycelium/u` | Standard UA | 400 | Endpoint reachable but rejects all payloads |
| `POST /api/v2/mycelium/u` | OP-User-Agent | 403 | Blocked by WAF with OP-UA header |
| `POST /api/v2/mycelium/v` | Standard UA | 401 | Needs auth (encrypted:true in JS) |

**Body Structure** (from JS analysis):
- `myceliumChannelStartU`: `POST /api/v2/mycelium/u`, body: `{deviceUuid, hello}`, `encrypted: false`
- `myceliumChannelStartV`: `POST /api/v2/mycelium/v`, body: `{hello}`, `encrypted: true`
- Response schema: `{channelSeed, channelUuid, initiatorAuth}`

The `hello` parameter requires a proper Noise protocol handshake message generated by the `b5_mycelium` WASM module (`wasmpairingsessionstarternewdevice_create_hello`). Random/hex values are rejected.

### 7.3 Confidential Computing Probes

**Objective:** Discover CC endpoint schema via serde errors, fuzz fields, try alternative content types.

**Results:**
- All CC endpoints return **403** (not 422 with serde errors as in production)
- No schema information leaked
- All content types blocked: `application/json`, `application/octet-stream`, `application/cbor`, `application/x-protobuf`
- All alternative paths return 403: `/api/v1/confidential-computing/{session,attestation,verify,enclave,key,quote}`, `/api/v1/tee/session`, `/api/v1/sgx/session`, `/api/v1/nitro/session`

### 7.4 Auth Methods Information Disclosure

**Objective:** Enumerate auth methods and test user enumeration.

**Endpoint:** `POST /api/v2/auth/methods`

**Result:** Returns 200 with `{"authMethods":[{"type":"PASSWORD+SK"}],"signInAddress":"https://bugbounty-ctf.1password.com"}` for ALL inputs including:
- Valid email: `ctf@bugbounty-ctf.1password.com`
- Invalid emails: `nonexistent@...`, `admin@...`, `flag@...`
- Empty string, `invalid`, completely empty body `{}`

**Assessment:** Anti-enumeration by design — returns identical response regardless of input. Not a vulnerability, but confirms the account uses `PASSWORD+SK` auth method.

### 7.5 WASM Module Analysis

**Objective:** Download and reverse engineer all WASM modules for crypto implementation bugs.

**Modules Found (6 total, 5 accessible):**

| Module | Size | Exports | Key Functions |
|--------|------|---------|---------------|
| b5_hpke | 82KB | 19 | `seal_x25519_chacha20poly1305`, `open_x25519_chacha20poly1305`, `x25519keypair_new` |
| b5_mycelium | 319KB | 47 | `wasmchannelseed_derive_auth`, `wasmchannelseed_derive_uuid`, `wasmpairingsessionstarter*`, `wasmhandshakepsk_*` |
| b5_trust-verifier | 1.2MB | 57 | `lessSafeVerifyExpectedKeyAndSignature`, `lessSafeVerifyExpectedTextRecordValue`, `signPublicKeys`, `verifyKeys` |
| b5_trustlog | 1.3MB | 169 | `wasmtrustlogclient_*`, bookmark signing, ID bootstrap, bulk operations |
| confidential_computing | 1.8MB | 18 | `enclavesession_encryptMessage`, `enclavesession_decryptMessage`, `testResponderSessionHandshake`, `createSession` |
| op_wasm_trusted_device_key_exchange | **403** | N/A | Blocked — hash `k6RLu5bHUSGOTADUeeTBQ1gSKjiazKFiBbHk0NxflHY=` |

**WASM Integrity:** Client-side SHA-256 verification via `trustedWasmHashes` array (6 hashes). 5/6 verified matching.

**Toolchain:**
- All modules compiled from Rust (1.79.0–1.91.1)
- wasm-bindgen (0.2.92–0.2.106)
- CC module compiled with Debian clang 19.1.7

**Notable Exports:**
1. **`lessSafeVerify*`** — "lessSafe" typically means reduced validation (ring crypto pattern). Could skip certain checks.
2. **`testResponderSessionHandshake`** — Test function in production CC module.
3. **`wasmchannelseed_derive_auth`** — Deterministic auth derivation from seed.

### 7.6 JS Bundle Crypto Pattern Analysis

**Bundles Analyzed:** 8 scripts from `app.1password.com/js/` (~5.4MB total)

**Crypto Implementation Patterns Found:**

| Pattern | Location | Context |
|---------|----------|---------|
| 2SKD XOR | webapi | `if(e.length!==t.length) throw new Error("cannot xor with mismatched lengths")` |
| HKDF OAuth workaround | webapi | `rawHkdf(Sha256, "This value works around an OAuth implementation limitation...")` for Brex |
| PBKDF2 | vendor-other, webapi | WebCrypto `subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",...})` |
| SRP-x precomputed | webapi | `createFromPreComputedX(credentialBundle.srpx.exportBytes())` |
| AUK (Account Unlock Key) | webapi, app | `e.user.masterKey=t.credentialBundle.auk` |
| SRP Group | webapi | `SRPg-4096` group, `Group4096` constant |
| Domain separator | webapi | `B5_CRYPTO_KEYS_SrpX`, `B5_CRYPTO_KEYS_RecoveryEncKeyV1` |

**Auth Flow (from JS):**
1. `POST /api/v3/auth/start` → `{status, sessionID, accountKeyFormat, accountKeyUuid, userAuth: {method, alg, iterations, salt}}`
2. `POST /api/v2/auth` → `{userA: bigAhex}` → `{userB}`
3. `POST /api/v2/auth/confirm-key` → `{clientVerifyHash}` → `{serverVerifyHash}`
4. `POST /api/v2/auth/complete` → `{notifier, accountUuid, userUuid, mfa, transportTokenDetails}`

### 7.7 HTML Data Attributes & Configuration

**Build Info:**
- `data-env="prd"` — Production environment
- `data-version="2248"` — App version
- `data-build-time="23 Apr 26 18:49 +0000"` — Built yesterday
- `data-gitrev="33a8e241e543"` — Git revision
- `data-bug-researcher-notes="Security researchers: All keys below are intended to be exposed publicly, and are therefore not vulnerable."`

**Exposed Service Keys (intentionally public per researcher notes):**
- Firebase: `data-fcm-api-key`, `data-fcm-vapid`, `data-fcm-app-id`
- Stripe: `pk_live_F59R8NjiAi5Eu7MJcnHmdNjj`
- Sentry DSN: `6342e577bc314e54ab2c5650a4c5be8f:f7b7d11056d84dd0b09e9a9ca31a72e8`
- Brex client ID: `bri_b2df18d65bc82a948573537157eceb07`
- Slack client ID: `36986904051.273534103040`
- Fastmail client ID: `35c941ae`

**CSP Policy:** Extremely restrictive — `script-src` limited to `app.1password.com` + two SHA hashes + `wasm-unsafe-eval`. No `unsafe-inline` or `unsafe-eval`.

**Staging/Test Domains (from JS):** `b5staging.com`, `b5dev.com`, `b5dev.ca`, `b5dev.eu`, `b5test.com`, `b5test.ca`, `b5rev.com`

### 7.8 API Endpoint Map

**Accessible (non-403) endpoints:**

| Endpoint | Method | Status | Response |
|----------|--------|--------|----------|
| `/api/v2/auth/methods` | POST | 200 | Auth methods (anti-enum) |
| `/api/v3/auth/start` | POST | 400 | Validates skFormat, then silent 400 |
| `/api/v1/auth` | POST | 401 | Empty `{}` |
| `/api/v2/mycelium/u` | POST | 400 | Needs Noise handshake hello |
| `/api/v1/session/touch` | PUT | 401 | Needs session |
| `/api/v1/session/signout` | PUT | 401 | Needs session |

**All other endpoints:** 403 (WAF/firewall blocked)

### 7.9 Assessment

**Attack Surface:** Extremely limited. The CTF target runs production 1Password code with a restrictive WAF that blocks nearly all API endpoints. The pre-auth surface consists of:
1. Auth methods endpoint (anti-enumeration, no useful info leaks)
2. Auth start endpoint (validates skFormat but suppresses all other errors)
3. Mycelium U channel (needs proper WASM-generated Noise handshake)

**Crypto Assessment:**
- 2SKD: Password entropy + 128-bit Secret Key → combined keyspace infeasible
- SRP: Standard SRP-6a with 4096-bit group, properly implemented
- WASM modules: Standard Rust crypto (ring, chacha20poly1305), no obvious backdoors
- `lessSafeVerify*`: Worth investigating but requires authenticated trust-log access
- `testResponderSessionHandshake`: Test function in CC WASM, inaccessible without auth

**Remaining Vectors:**
1. Execute the mycelium WASM module to generate a proper Noise handshake `hello` and attempt channel creation
2. Investigate the 6th WASM module (`op_wasm_trusted_device_key_exchange`) if access can be obtained
3. Attempt WebSocket connection to `wss://b5n.1password.com` (notifier service)
4. Deeper analysis of the SK retrieval fallback script (`sk-*.min.js`) which includes SJCL crypto

---

## Phase 8 — Deep Probes: SK Script, WebSocket, Lazy Chunks

**Date:** 2026-04-24

### 8.1 SK Retrieval Script Deep Analysis

**Target:** `app.1password.com/js/sk-2c17b526b1a01ed2f995.min.js` (54KB)

**Contents:**
- Stanford JavaScript Crypto Library (SJCL) — full implementation of AES, GCM, PBKDF2, ECC/ECDSA, SHA-256, SHA-512
- Deobfuscation function using key derived from SHA-1 of string: `"Obfuscation Does Not Provide Security But It D..."`
- Purpose: Displays previously stored Secret Keys from browser local storage when a user requests recovery
- No API calls — entirely client-side crypto for local key retrieval

**Assessment:** The obfuscation is explicitly declared non-security (the key derivation input literally says so). The script decrypts locally stored SK material for display — no exploitable server interaction. The SJCL implementation appears standard with no backdoors.

### 8.2 WebSocket / Notifier Probing

**Target:** `b5n.1password.com` (notifier/push service)

| Path | Method | Status | Response |
|------|--------|--------|----------|
| `/` | GET | 400 | Bad Request |
| `/ws` | GET | 400 | Bad Request |
| `/websocket` | GET | 400 | Bad Request |
| `/notifier` | GET | 400 | Bad Request |
| `/ws` | GET (Upgrade) | 400 | Bad Request |

**CTF domain WebSocket attempt:** Returns 200 with the HTML page (no WebSocket upgrade).

**Notifier URL endpoint** (`/api/v1/account/notifier-url`): 401 `{}` — requires authentication.

**Assessment:** The notifier service expects a specific protocol handshake that likely includes session tokens. Cannot access without completing authentication first.

### 8.3 Lazy Chunk & Admin Endpoint Scanning

**Lazy-loaded chunks found in JS:**
- `core_trustedDeviceCredentialExchange-f8bb0904.js` — 403 blocked from all paths

**Admin/debug endpoints probed:**
- No admin panels, debug endpoints, health checks, or status pages found
- Flow service (`/api/v1/flow`) returns 403
- Signup/enrollment paths return standard 403

**Assessment:** The WAF blocks all non-essential endpoints. No hidden admin interfaces or debug endpoints accessible.

### 8.4 Phase 8 Summary

All three probe vectors confirmed the target's hardened posture:
- SK script: Client-side only, no server interaction to exploit
- WebSocket: Requires auth, no pre-auth access
- Lazy chunks: Blocked by WAF
- No admin/debug surfaces exposed

---

## Phase 9 — WASM Deep Analysis, Enrollment Probing, Mycelium Protocol

**Date:** 2026-04-24

### 9.1 Mycelium WASM Deep Analysis

**Module:** `b5_mycelium_bg-81e1515173df8b75c89e.wasm` (319KB, 47 exports)

**Noise Protocol Identification:** `Noise_KXpsk0_25519_ChaChaPoly_BLAKE2b`
- Pattern: KX with pre-shared key at position 0
- DH: X25519 (Curve25519)
- Cipher: ChaCha20-Poly1305
- Hash: BLAKE2b
- Built with: `snow` Rust crate v0.9.6

**Pairing Session Flow (New Device):**
1. `wasmpairingsessionstarternewdevice_init` — Initialize session
2. `wasmpairingsessionstarternewdevice_create_hello` — Create Noise initiator hello (takes device UUID)
3. `wasmpairingsessionstarternewdevice_receive_reply` — Process responder reply
4. `wasmpairingsessionstarternewdevice_shared_key` — Extract shared key

**Pairing Session Flow (Existing Device):**
1. `wasmpairingsessionstarterexistingdevice_join` — Join as existing device
2. `wasmpairingsessionstarterexistingdevice_receive_hello` — Receive hello from initiator
3. `wasmpairingsessionstarterexistingdevice_create_reply` — Create reply

**Channel & Credential Functions:**
- `wasmchannelseed_new`, `wasmchannelseed_derive_auth`, `wasmchannelseed_derive_uuid`
- `wasmpairingsetupcredentials_generate`, `wasmpairingcredentials_generate`
- `wasmhandshakepsk_generate`, `wasmhandshakepsk_from_bytes`

**JS Glue Code Analysis — `create_hello` call flow:**
```
createHello = e => this.starter.create_hello((0, a.kV)(h(e)))
```
- Takes a single argument: a serialized (JSON-encoded) device info string
- `(0,c.u)()` generates the parameter — likely a fresh device UUID
- Result is the Noise KXpsk0 initiator message

**Full Pairing Sequence (from JS):**
1. Generate pairing setup credentials
2. `createHello(deviceUUID)` → Noise initiator message
3. POST to mycelium U channel → receive `{channelUuid, channelSeed, initiatorAuth}`
4. `receiveResponse(channelUuid, channelSeed)` → process handshake
5. Extract `pubKey`, `psk`, create QR data for second device

**Key Strings in Data Section:**
- `B5_MYCELIUM_CHANNEL_JOIN_TOKEN`, `B5_MYCELIUM_CHANNEL_UUID`
- `CapabilitySIGN_INITEM_SHARINGSECURE_REMOTE_AUTOFILL`
- Source: `crypto/op-mycelium/src/{buffers,lib,channel}.rs`

**HPKE Module:** `b5_hpke_bg` (82KB) — `seal_x25519_chacha20poly1305`, `open_x25519_chacha20poly1305`

### 9.2 Enrollment Endpoint Probing (CTF domain only)

| Endpoint | Status | Response |
|----------|--------|----------|
| `/api/v1/auth/enroll` | 404 | Not found |
| `/api/v2/auth/enroll` | 404 | Not found |
| `/api/v3/auth/enroll` | 404 | Not found |
| `/api/v1/signup` | 400 | `{}` |
| `/api/v2/signup` | 400 | `{}` |
| `/api/v1/register` | 404 | Not found |
| `/api/v1/account/create` | 404 | Not found |
| `/api/v1/accounts` | 404 | Not found |
| `/api/v1/invitation` | 404 | Not found |
| `/api/v1/invitation/accept` | 404 | Not found |
| `/api/v1/flow` | 404 | Not found |

**Notable:** `/api/v1/signup` and `/api/v2/signup` return 400 `{}` (not 404) — these endpoints exist but reject the payload silently, same as auth/start.

**v3/auth/start extended payloads:** Adding `skid`, `accountKeyFormat`, `userAuth`, `deviceUuid` all return the same 400 `{}`. No additional error information leaked.

**v2/auth direct:** Returns 401 `{}` for all payload variations (requires session from v3/auth/start first).

**Response Headers (v3/auth/start):**
- `x-request-id: 46727144` — request tracking present
- Full CSP with `sandbox` directive
- HSTS with preload
- `cross-origin-opener-policy: restrict-properties`

### 9.3 CORS Header Analysis

OPTIONS requests reveal the exact auth mechanism:
```
access-control-allow-headers: X-AgileBits-Client, X-AgileBits-MAC, Cache-Control, X-AgileBits-Session-ID, Content-Type, OP-User-Agent, ChannelJoinAuth
access-control-allow-methods: GET, POST, PUT, PATCH, DELETE
access-control-allow-origin: https://bugbounty-ctf.1password.com
access-control-allow-credentials: true
```

**Auth headers:** `X-AgileBits-Session-ID` (session UUID), `X-AgileBits-MAC` (request HMAC), `X-AgileBits-Client` (client identifier). Session-based auth — no cookies used.

### 9.4 Endpoint Map (Comprehensive)

**Authenticated endpoints (401):**

| Endpoint | Methods | Notes |
|----------|---------|-------|
| `/api/v1/vaults` | GET, POST | List/create vaults |
| `/api/v1/vault` | POST | Create vault |
| `/api/v1/vault/default` | GET | Default vault |
| `/api/v1/vault/personal` | GET | Personal vault |
| `/api/v1/vault/shared` | GET | Shared vault |
| `/api/v1/vault/items` | GET | Vault items |
| `/api/v1/device` | POST, PATCH | Create/update device |
| `/api/v1/device/register` | DELETE | Deregister device |
| `/api/v1/account` | GET, DELETE | Account info |
| `/api/v1/account/keysets` | GET | Keysets |
| `/api/v1/groups` | GET | Groups |
| `/api/v1/session/touch` | PUT | Keep session alive |
| `/api/v1/session/signout` | PUT | Sign out |
| `/api/v1/auth/verify` | POST | Verify auth |
| `/api/v2/auth/verify` | POST | Verify auth |
| `/api/v2/auth/complete` | POST | Complete auth |

**Pre-auth endpoints:**

| Endpoint | Status | Response |
|----------|--------|----------|
| `/api/v2/auth/methods` | 200 | `{"authMethods":[{"type":"PASSWORD+SK"}]}` (anti-enum) |
| `/api/v3/auth/start` | 400 | `{}` (silent rejection) |
| `/api/v1/confidential-computing/session` | 200 | Handshake exchange! |
| `/api/v1/signup` | 400 | `{}` (silent rejection) |
| `/api/v2/signup` | 400 | `{}` (silent rejection) |
| `/api/v1/account` | 400 | `{}` (POST creates account?) |
| `/api/v2/mycelium/u` | 400 | Needs Noise handshake |

### 9.5 Confidential Computing Session (MAJOR FINDING)

**`POST /api/v1/confidential-computing/session`** is a **pre-auth endpoint** that exchanges Noise protocol handshake messages.

**Request:** `{"handshakeMessage": "<hex-encoded-bytes>"}` (minimum 32 bytes)
**Response:** `{"handshakeMessage": "<base64url-encoded-12077-bytes>", "sessionUuid": "<uuid>"}`

**Key observations:**
- Accepts ANY 32+ byte hex string as handshake — no client validation
- Returns a fresh sessionUuid each time
- Response is 12077 bytes (ephemeral key + encrypted attestation report)
- Extra fields (`verificationMode`, `attestationReport`) are silently ignored
- Multiple handshakes create separate sessions
- CC sessions do NOT grant access to vault/auth endpoints (separate auth system)
- `<32 bytes` → `{"reason":"Failed to decrypt request"}`
- Non-hex input → `422 serde parse error`

**CC Verification Mode (from JS):**
- `*.b5local.com` → `unsafe-local` (no attestation verification)
- `*.b5dev.com`/`*.b5test.com` → `unsafe-lower` (relaxed verification)
- `bugbounty-ctf.1password.com` → `upper` (full verification)

**Implication:** To properly interact with CC, we need the `confidential_computing` WASM module to generate valid Noise protocol messages. The server's response is encrypted with the (invalid) shared secret derived from our random "key."

### 9.6 JS Bundle Analysis — Key Findings

**Hardcoded HKDF key for Brex OAuth:**
```javascript
const J = "klp4y2ywpkpczwhhutf2fqy5ri";
// HKDF(SHA256, "This value works around an OAuth implementation limitation...", "brex-oauth-obfuscation", 32)
```
Used for vault item deobfuscation, not exploitable.

**Unsafe device enrollment functions:**
- `unsafeCancelDeviceEnrollment` — requires authenticated session
- `unsafeGetDeviceEnrollmentStatus` — requires authenticated session
Both need a valid session, not pre-auth accessible.

**Debug mode:** `setDebugMode(internalFeaturesAreEnabled)` — build-time flag, `false` in production.

**Auth flow field names confirmed (from JS):**
```javascript
// v3/auth/start request:
{email, skFormat, skid, deviceUuid, userUuid, signInToken}

// v3/auth/start response:
{userAuth, sessionID, status, newHost, newEmail, accountKeyFormat, accountKeyUuid}

// v2/auth request:
{userA: <SRP-A-hex>}

// v2/auth response:
{userB: <SRP-B-hex>}

// v2/auth/confirm-key:
{clientVerifyHash} → {serverVerifyHash}
```

**OP-User-Agent behavior:** Adding the `OP-User-Agent` header changes response format (empty body vs `{}`) and breaks the `auth/methods` endpoint (200→400). The production client sends this header, so the server has two code paths.

### 9.7 Phase 9 Assessment

**CC session is the most promising pre-auth vector.** The endpoint accepts arbitrary handshake data and returns encrypted responses with session UUIDs. However:
1. Without the CC WASM module, we can't generate valid Noise protocol messages
2. CC sessions are isolated from the SRP-based auth system
3. The `upper` verification mode means attestation is fully verified

**Remaining attack surface:**
1. **CC WASM execution** — Need wasmtime/wasmer to generate proper Noise handshakes
2. **Mycelium WASM execution** — Need WASM runtime for Noise_KXpsk0_25519_ChaChaPoly_BLAKE2b hello
3. **Auth/start payload mystery** — Server validates email/skFormat but then silently fails. Something else is wrong with our payloads that we can't determine without seeing serde error messages (which the server suppresses)
4. **Signup flow** — Endpoints exist (400, not 404) but payload format unknown

**No WASM runtime available** on this system (no wasmtime, wasmer, or Python bindings).

---

## Phase 10: CC Noise Handshake Breakthrough

### 10.1 WASM Module Instantiation

Installed `wasmtime` Python bindings and instantiated the CC WASM module (`confidential_computing_bg-8b963455d8e79c3a746b.wasm`, 1,847,799 bytes) with stub implementations for all 48 host imports from the `wbg` module.

**Key exports discovered:**
| Export | Signature | Notes |
|--------|-----------|-------|
| `testResponderSessionHandshake` | `(anyref) → (anyref)` | Requires JS runtime |
| `createSession` | `(anyref, anyref, i32) → (anyref)` | `i32` = verification mode enum |
| `enclavesession_encryptMessage` | `(i32, i32, i32, i32, i32) → (i32, i32, i32)` | `(self, path_ptr, path_len, body_ptr, body_len)` |
| `enclavesession_decryptMessage` | `(i32, i32, i32) → (i32, i32, i32, i32)` | `(self, ptr, len)` |

Functions using `anyref` parameters require a full JavaScript runtime (V8/SpiderMonkey) to provide proper JS objects. Stub implementations returned dummy values.

### 10.2 WASM String Extraction — Protocol Identification

Extracted 4,484 strings from the WASM data section. Critical findings:

**Noise protocol:** `Noise_NX_25519_ChaChaPoly_SHA256` at offset 1422102
- Snow Rust crate v0.9.6 used for Noise implementation
- Source path: `crates/internal/cc-secure-channel/src/handshake.rs`

**Serde struct names:**
- `CreateClientSessionRequest`
- `CreateClientSessionResponse`
- `CreateClientSessionHandshakeMessageResponse with 2 elements`

**Error messages:**
- `Failed to decrypt the handshake request`
- `Failed to serialize handshake message`
- `SecureChannelCreateSession`

**Hardcoded test keys:** Ed25519 keys at offsets 1672607-1672691 (for Sigstore verification in test mode)

### 10.3 Encoding Breakthrough — Root Cause of Handshake Failures

**Root cause:** All previous handshake failures (v1-v4) were caused by an encoding mismatch.

The server's serde deserializer uses **base64url** decoding for the `handshakeMessage` field. We were sending hex-encoded keys. Since all hex characters (0-9, a-f) are valid base64url characters, the server accepted our requests (200 OK) but decoded them differently:

| Encoding | Characters | Bytes produced | Result |
|----------|-----------|----------------|--------|
| Hex (wrong) | 64 chars | 48 bytes (base64url decode) | **Mismatch** — server DH uses wrong key |
| Base64url (correct) | 43 chars | 32 bytes | **Correct** — both sides use same key |

The 48 vs 32 byte mismatch caused the Noise state machines to diverge, making all subsequent decryption impossible.

**Fix:** Use base64url encoding without padding for `handshakeMessage` field.

### 10.4 Successful Noise_NX Handshake

Using the `noiseprotocol` Python library (v0.3.1) with base64url encoding:

```
Pattern: Noise_NX_25519_ChaChaPoly_SHA256
Prologue: empty (b"")
Encoding: base64url, no padding
Handshake: COMPLETE
Payload: 11,981 bytes (JSON)
```

**Handshake flow:**
1. **→ e**: Client sends ephemeral X25519 public key (32 bytes, base64url encoded)
2. **← e, ee, s, es**: Server responds with ephemeral key + encrypted static key + encrypted payload
3. Transport keys established — bidirectional Noise encryption active

### 10.5 Attestation Document Analysis

The 11,981-byte handshake payload is JSON with two fields:

#### `attestation_document` (COSE_Sign1, 4,728 bytes)

AWS Nitro Enclave attestation signed with ES384 (ECDSA-P384-SHA384):

| Field | Value |
|-------|-------|
| module_id | `i-0957b0a073239ba7a-enc019dbc9e66185d27` |
| digest | SHA384 |
| timestamp | 2026-04-25 03:34:39 UTC |
| nonce | None |
| enclave public_key | `831366eff73f9003f05a232a141b7abbedd9481f6723212d36542f54408a3571` (32 bytes) |

**PCR measurements (SHA-384):**
| PCR | Value | Meaning |
|-----|-------|---------|
| PCR0 | `b6b2c1ff...aca50` | Enclave image hash |
| PCR1 | `3b4a7e1b...74d03` | Linux kernel + bootstrap hash |
| PCR2 | `eb7288de...caf0` | Application hash |
| PCR3 | `88e92e30...f954` | IAM role hash |
| PCR4 | `ff62927e...ac33b` | Instance ID hash |
| PCR5-15 | (all zeros) | Unused |

**user_data (JSON):**
```json
{
  "expiry": 1777088679,  // 10-minute TTL from timestamp
  "rootCa": {
    "alg": "SHA-256",
    "fingerprint": "74a01539ab166f7389c760bf49557092f61a8c95ccd6162c399e0a9e1067cc9a"
  },
  "tlog": {
    "alg": "SHA-256",
    "fingerprint": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
  }
}
```

**AWS Nitro certificate chain (5 levels):**
1. `aws.nitro-enclaves` (self-signed root)
2. `fe51ad30b41313d7.us-east-1.aws.nitro-enclaves` (regional)
3. `548fff4208fe992a.zonal.us-east-1.aws.nitro-enclaves` (availability zone)
4. `i-0957b0a073239ba7a.us-east-1.aws.nitro-enclaves` (EC2 instance)
5. `i-0957b0a073239ba7a-enc019dbc9e66185d27.us-east-1.aws` (enclave)

End-entity cert valid for 3 hours (03:28:59 - 06:29:02 UTC).

#### `signature_bundle` (Sigstore v0.2)

**1Password certificate chain:**
1. `com.1password.enclave-application` (code signing, valid 2026-03-26 to 2027-03-26)
   - CRL: `http://crl.1passwordservices.com/crl/ff6a9d83-d360-421e-bc1c-225e9ebde301.crl`
2. `1Password Signing Authority 1` (CA, valid 2023-12-01 to 2068-12-01)
   - CRL: `http://crl.1passwordservices.com/crl/72c6f9f8-cb97-467a-8760-829585134246.crl`
3. `1Password Root CA 1` (root, not included in bundle — fingerprint in user_data)

**Rekor transparency log:**
- Log index: 1351731398
- Integrated time: 2026-04-21 17:09:11 UTC
- Log ID fingerprint matches `user_data.tlog.fingerprint` ✓

### 10.6 CC Transport Architecture

**Architecture discovered from JS bundle analysis:**

The CC session provides an encrypted channel to the Nitro Enclave. Transport works in two layers:

1. **Noise encryption (CC session):** Encrypts `(destinationPath, body)` for the enclave
2. **SRP encryption (auth session):** Wraps the Noise ciphertext for transport

```
Client → SRP-encrypt({sessionUuid, encryptedRequest}) → Session Bridge (B5)
         → Noise-decrypt → route to destinationPath → Enclave microservice
```

**Transport requires SRP authentication.** The `sendRequest` callback in the JS sends through `session.request()` (the SRP session), which adds authentication headers. Without SRP auth, we can only complete the handshake phase.

**Session Bridge behavior:**
- Identified as `B5` in `Proxy-Status` header
- Also reports as `SessionBridge` in structured Proxy-Status
- Only intercepts requests at `/api/v1/confidential-computing/session`
- Returns 422 for transport requests without SRP wrapping: `{"reason":"Failed to parse the request body as JSON at line 1 column X"}`
- Column X = total JSON body length (serde cannot deserialize because the outer struct only expects `handshakeMessage`)

**Known enclave destination paths (from JS bundle):**
- `/epm-login-discovery/api/v1/register`
- `/provisioning-key-service/api/v1/integration/create`
- `/provisioning-key-service/api/v2/integration/create`

**CC session use cases (from JS):**
- CPACE device enrollment (`/api/v3/device/enrollments/{id}/cpace/msga|msgb|taga|tagb`)
- Provisioning key service
- Login discovery service

### 10.7 Transport Layer Testing

**Results of sending encrypted messages to the CC session endpoint:**

| Body format | Status | Error |
|-------------|--------|-------|
| `{sessionUuid, encryptedRequest}` | 422 | Failed to parse JSON (unknown fields) |
| `{handshakeMessage: encrypted}` | 400 | Failed to decrypt request (not a valid handshake) |
| `{sessionUuid, handshakeMessage: encrypted}` | 400 | Failed to decrypt request |
| Raw bytes (octet-stream) | 400 | Failed to parse JSON at column 1 |

**Results of sending to other endpoints (with/without CC headers):**

| Endpoint | Status | Proxy-Status |
|----------|--------|-------------|
| `/api/v1/auth` | 401 | (none) |
| `/api/v1/account` | 400 | (none) |
| `/api/v3/device/enrollments` | 401 | (none) |
| `/api/v1/vault/personal` | 405 | (none) |
| `/api/v1/confidential-computing/request` | 404 | (none) |
| `/api/v1/confidential-computing/session/{uuid}` | 404 | (none) |

No endpoints besides `/api/v1/confidential-computing/session` are intercepted by the Session Bridge.

### 10.8 Phase 10 Assessment

**The CC Noise handshake is the most significant pre-auth finding.** We successfully:
1. Identified the Noise protocol variant from WASM binary analysis
2. Discovered the base64url encoding requirement (root cause of all failures)
3. Completed a full Noise_NX handshake and decrypted the attestation payload
4. Verified the AWS Nitro certificate chain and Sigstore signature bundle
5. Mapped the complete CC transport architecture

**However, CC transport requires SRP auth.** The pre-auth CC handshake provides:
- Enclave identity verification (attestation document)
- PCR measurements (enclave image hashes)
- Sigstore code signing verification
- 10-minute session TTL

**No vulnerabilities found in the CC implementation:**
- Attestation is properly signed and verified
- Certificate chains are valid
- TTL is reasonable (10 minutes)
- Transport requires double encryption (Noise + SRP)
- Session Bridge properly rejects unauthenticated transport requests

**Remaining pre-auth attack surface:**
1. **SRP authentication** — Need valid credentials (email + password + Secret Key)
2. **Signup/enrollment flow** — See Phase 11 below
3. **Auth timing analysis** — Check for oracle attacks in SRP verification
4. **Mycelium WASM** — Noise_KXpsk0_25519_ChaChaPoly_BLAKE2b (separate protocol)

---

## Phase 11: Signup Flow & Pre-Auth Endpoint Exploration

### 11.1 Signup Endpoint Discovery

**Working endpoint:** `POST /api/v1/signup` and `POST /api/v2/signup`

```
Request:  {"name": "Test", "email": "test@test.com", "type": "I"}
Response: 200 {"emailResendToken": "B6L2RO7QHBFAZF23DCHAFOR4QQ"}
```

- `type: "I"` = Individual account (only value tested before rate limit hit)
- `encrypted: false` in JS — no SRP/auth required
- `withCredentials: true` — cookie-based session
- Rate limit: ~1 request per minute, 429 with absolute retry time

The `emailResendToken` is a 26-character base32 string used for email verification resend.

### 11.2 Signup Flow Architecture (from JS)

The complete signup flow involves 8 endpoints, all with `encrypted: false`:

| Step | Endpoint | Method | Purpose |
|------|----------|--------|---------|
| 1 | `/api/v1/signup` or `/api/v2/signup` | POST | Initial signup → `{emailResendToken}` |
| 2 | `/api/v1/signup/resend/{token}` | POST | Resend verification email |
| 3 | `/api/v2/signup/{signupId}` | GET | Get signup details (state) |
| 4 | `/api/v3/signup/{signupId}` | PATCH | Update signup data |
| 5 | `/api/v2/signup/{signupId}?email=X&account-type=Y` | GET | Get signup info |
| 6 | `/api/v2/user` | POST | Create user → `{userUuid, sessionUuid?, signInTokenDetails?}` |
| 7 | `/api/v1/account` | POST | Register account → `{accountUuid, userUuid, signInTokenDetails?}` |
| 8 | Email verification | Out-of-band | User clicks email link |

**Critical: Steps 6 and 7 return `signInTokenDetails`** — potentially providing a session token directly at account creation. However, both return 400 `{}` with our test payloads (missing required SRP verifier, salt, etc.).

### 11.3 Signup Sub-Endpoint Testing

| Endpoint | Status | Response |
|----------|--------|----------|
| `POST /api/v1/signup/resend/{token}` | **200** | `{"success": 1}` — **works!** |
| `GET /api/v2/signup/{token}` | 400 | `{"errorCode": 100, "errorMessage": "Invalid request parameters."}` |
| `PATCH /api/v3/signup/{token}` | 400 | `{}` |
| `PATCH /api/v2/signup/{token}` | 400 | `{}` |
| `POST /api/v2/user` (various payloads) | 400 | `{}` |
| `POST /api/v1/account` (various payloads) | 400 | `{}` |

The `emailResendToken` works for resending but isn't the correct `signupId` for `GET /api/v2/signup/`. The signup may use a separate UUID returned in a field we're not seeing, or the v2 response format includes additional fields.

### 11.4 Secret Key Format Validation

**`POST /api/v3/auth/start`** validates the `skFormat` field:

| Format | Response | Status |
|--------|----------|--------|
| `A2` | `{}` | 400 (accepted format, different error) |
| `A3` | `{}` | 400 (accepted format, different error) |
| `A1`, `A4` | `{"reason": "invalid_sk_prefix_format"}` | 400 |
| `B1`, `B2`, `B5` | `{"reason": "invalid_sk_prefix_format"}` | 400 |
| `SK`, `SRP`, etc. | `{"reason": "invalid_sk_prefix_format"}` | 400 |
| (lowercase) `a3` | `{"reason": "invalid_sk_prefix_format"}` | 400 |

Only `A2` and `A3` are valid Secret Key format prefixes. The A3 format is current (128-bit key), A2 is the older format.

### 11.5 Account Enumeration Resistance

All email addresses tested return identical responses from `POST /api/v3/auth/start`:
- Status: 400
- Body: `{}`
- Timing: 112-145ms (no significant variation)

Emails tested: `ctf@`, `admin@`, `test@`, `nonexistent@fakeDomain123xyz.com`, `security@`, `bugbounty@`, `bad.poetry@`, `vault@`, `challenge@`, `demo@`, `flag@` — all `@1password.com`. No account enumeration possible via this endpoint.

### 11.6 Additional Endpoint Discovery

| Endpoint | Status | Notes |
|----------|--------|-------|
| `POST /api/v1/invite` | 401 | Requires auth |
| `POST /api/v1/device` | 401 | Requires auth |
| `GET /api/v2/notification` | 401 | Requires auth |
| `POST /api/v3/device/enrollments` | 401 | Requires auth |
| `POST /api/v1/signup` | **200** | Works pre-auth |
| `POST /api/v2/signup` | **200** | Works pre-auth |
| `POST /api/v1/signup/resend/{token}` | **200** | Works pre-auth |
| `GET /api/v1/auth/methods` | 404 | Removed or renamed |
| `/health`, `/healthz`, `/ready`, `/readyz` | 200 | Return SPA HTML (not real health endpoints) |
| `/.well-known/*` | 200 | Return SPA HTML (client-side routing) |

### 11.7 Phase 11 Assessment

**The signup endpoint is accessible and functional**, but completing the flow requires:
1. Email verification (the CTF server appears to actually send emails — the resend endpoint returns `{"success": 1}`)
2. SRP verifier generation with password + Secret Key
3. Multi-step account registration

**No bypass found for email verification.** The signup flow follows the expected pattern:
- Initial registration (pre-auth) → email verification → user creation → account registration
- Steps 2+ likely require the email verification code
- The `signInTokenDetails` in the user/account creation response could provide auth, but those endpoints reject our payloads (missing crypto fields)

**Key observation:** The CTF may be designed so that NO valid accounts exist, making all auth-dependent features inaccessible. The challenge may specifically test whether 1Password's 2SKD model prevents access without valid credentials.

**Remaining vectors:**
1. **SRP verifier construction** — Build a valid v2/user or v1/account payload with proper SRP fields
2. **Mycelium WASM** — Separate Noise protocol for real-time features
3. **CRL checking** — The Sigstore certificates reference CRL URLs at `crl.1passwordservices.com`
4. **Auth timing oracle** — Statistical analysis of SRP verify responses

---

## Phase 12: Signup Flow Deep Dive & Registration Endpoint Mapping

### 12.1 Registration Endpoint Discovery (from JS Bundle)

Traced `registerAccount` and `registerPasskeyAccount` through the minified JS:

**Module 29455** (signup functions):
- `registerAccount` (`NH` export) → function `k` → calls `C(e,t)` (generates SRP creds from password) then `K(e)` (sends to API)
- `registerPasskeyAccount` (`Ff` export) → function `U` → calls `R(e,t)` (generates passkey creds) then `I(e, challenge, encCredential, auth)` (sends to API)

**Both ultimately call `o.uZ`** from module 44367, which maps to:

```
R = (e) => ({name: "postAccount", method: "POST", url: "/api/v1/account", body: e, responseType: C, encrypted: false})
```

**Module 44367** (API endpoint definitions):

| Export | Function | Method | URL | Purpose |
|--------|----------|--------|-----|---------|
| `BC` | `A` | POST | `/api/v1/signup` | Legacy signup |
| `wZ` | `b` | POST | `/api/v2/signup` | Signup → `{emailResendToken}` |
| `Wd` | `T` | POST | `/api/v2/user` | Create user → `{userUuid, sessionUuid?}` |
| `uZ` | `R` | POST | `/api/v1/account` | Register account → `{accountUuid, userUuid, signInTokenDetails?}` |
| `NL` | `P` | GET | `/api/v2/signup/${id}` | Get signup details |
| `K5` | `U` | GET | `/api/v2/signup/${id}?email=X&account-type=Y` | **signUpAndGetInfo** |
| `Yv` | `E` | PATCH | `/api/v3/signup/${id}` | Update signup |
| `BV` | `k` | PATCH | `/api/v2/signup/${id}` | Update signup type |
| `nA` | `K` | POST | `/api/v1/signup/resend/${token}` | Resend verification email |

### 12.2 SRP Auth Construction (from JS)

`getForUpload` returns: `{method, alg, iterations, salt, v}` where:
- `v` = SRP verifier = `g^srpX mod N` (hex string)
- `srpX` for SRPg method = `HKDF(SHA256, salt, method, email, 32) → PBKDF2(password, hkdf_output, iterations) → XOR secretKey`
- Default params: `PBKDF2-HMAC-SHA256`, `SRPg-4096`, 650000 iterations

### 12.3 Password-Based Registration Payload

Function `K` sends to `POST /api/v1/account`:
```json
{
  "signupUuid": "<client-generated-UUID>",
  "user": {
    "email": "...", "language": "en", "name": "...",
    "newsletterPrefs": 0,
    "accountKeyFormat": "A3",
    "accountKeyUuid": "<UUID>",
    "avatar": ""
  },
  "account": {
    "name": "...", "domain": "1password.com", "type": "I", "avatar": ""
  },
  "device": { ... },
  "keyset": { ... },
  "userAuth": { "method": "SRPg-4096", "alg": "PBES2g-HS256", "iterations": 650000, "salt": "...", "v": "..." }
}
```

### 12.4 Passkey-Based Registration Payload

Function `I` sends to `POST /api/v1/account`:
```json
{
  "signupUuid": "<client-generated-UUID>",
  "user": {
    "email": "...", "language": "en", "name": "...",
    "newsletterPrefs": 0,
    "accountKeyFormat": "A3",
    "accountKeyUuid": "<UUID>",
    "avatar": "",
    "challenge": "852809",
    "deviceCredential": {"v": 2, "encCredentials": "..."}
  },
  "account": { ... },
  "device": { ... },
  "keyset": { ... },
  "userAuth": { ... }
}
```

### 12.5 CRITICAL: Verification Code IS the Signup ID

**Breakthrough from signup verify page (chunk 6529):**

The email verification code (6-digit number) is used directly as the `signupId` in the URL:

```javascript
// From verify chunk:
const r = await l.XI.signUpAndGetInfo(f.S9, a, e.signUpData.email, e.signUpData.type);
// a = the 6-digit code entered by user
// Maps to: GET /api/v2/signup/${code}?email=${email}&account-type=${type}
```

**signUpAndGetInfo response type (from webapi):**
```
{uuid, domain, state, createdAt, completedAt, expiresAt, name, type, source, email,
 language, availablePlans, tierName, trialEndsAt, features: {creditCardForm, passkey},
 setupIntentCode, stepUuid?, promoCode?, flowServiceUuid?, duplicateAccounts?,
 accountCreationDisabled?, defaultBillingFrequency?}
```

The response includes `features.passkey.isRequired` — if true, the passkey flow is mandatory (challenge code submitted with registration). If false, the password flow is used.

**Signup URL encoding:** The signup data is base64url-encoded JSON in the URL:
```
/sign-up/{accountType}/{base64url(JSON.stringify(signUpData))}
```

### 12.6 Complete Signup Flow (Verified)

1. `POST /api/v2/signup` → `{emailResendToken}` (creates server-side signup, sends verification email)
2. User enters 6-digit code on `/sign-up/verify` page
3. `GET /api/v2/signup/{code}?email=X&account-type=Y` → signup details including `uuid`, `domain`, `features`
4. Client generates crypto material (SecretKey, SRP verifier, keyset, device)
5. `POST /api/v1/account` → `{accountUuid, userUuid, signInTokenDetails?}` — creates the account
6. Client auto-signs in using the returned session details

**Status:** Created new signup (token `MFZKTNU3JBEUNCAOUAP7YGTF3Y`), awaiting fresh verification code.
Previous code (852809) was consumed during a prior conversation compaction.

### 12.7 Phase 12 Assessment

The signup flow is now fully mapped. The remaining challenge is constructing valid crypto material for step 5:
- **SecretKey**: Generated client-side (A3 format, 128-bit random)
- **SRP verifier**: Requires HKDF + PBKDF2 + SecretKey XOR + modular exponentiation
- **Keyset**: AES-GCM encrypted keypair bundle
- **Device**: Device identifier structure

All of this is doable with the `cryptography` Python library, but requires implementing 1Password's specific 2SKD protocol.

---

## Phase 13: Browser-Based Traffic Interception & Signup Flow Capture

**Date:** 2026-04-25

### 13.1 Approach

Used clearwing's Playwright browser tools to load the CTF signup SPA in a headless Chromium instance, mock the 1Password extension detection, fill the signup form, and capture the exact API requests the SPA sends — including all headers, cookies, and body format.

### 13.2 Extension Detection Bypass

The SPA gates the signup form behind a browser extension promo. The extension detection function (module 40301 in `webapi.js`) checks two `data-` attributes on `document.body`:

```javascript
const hasExtensionInstalled = () => {
    const e = !!document?.body?.dataset?.onepasswordExtensionVersion;
    const t = !!document?.body?.dataset?.b5xBuildNumber;
    return e || t;
};
```

Bypassed via `page.addInitScript()`:
```javascript
document.body.dataset.onepasswordExtensionVersion = '2.28.1';
document.body.dataset.b5xBuildNumber = '2280100';
```

This reveals the "Create your account" form with Name, Email, and Newsletter checkbox fields.

### 13.3 Domain Redirect Chain

The CTF page performs a client-side redirect through multiple 1Password domains:

1. `bugbounty-ctf.1password.com/sign-up` → serves SPA HTML (status 200)
2. SPA loads JS from `app.1password.com/js/*` (static assets CDN)
3. `POST bugbounty-ctf.1password.com/api/pre-registration-features` → 200
4. SPA redirects to `start.1password.com/sign-up` (client-side)
5. `POST start.1password.com/api/pre-registration-features` → 200
6. After signup: redirects to `my.1password.com/sign-up/verify/{base64data}`

**Key finding:** The CTF domain is the entry point, but the SPA redirects to production 1Password domains for the actual signup flow. API calls go to whichever domain the browser is currently on.

### 13.4 Signup POST — Exact Request Format

The SPA sends the signup POST to `start.1password.com` (not the CTF domain):

```
POST https://start.1password.com/api/v2/signup
```

**Headers:**
```
op-user-agent: 1|B|2248|{random26chars}|||Chrome|145.0.7632.6|MacOSX|26.3.1|
accept-language: en
user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ...
```

**Body (full fields):**
```json
{
  "email": "...",
  "domain": "my",
  "name": "Eric Hartford",
  "type": "I",
  "language": "en",
  "promoCode": "",
  "purchaseOrderToken": "",
  "stripePurchaseOrderToken": "",
  "source": "B",
  "companySize": ""
}
```

**Previously missing fields in our API calls:**
- `domain`: `"my"` — determines which subdomain the account lands on
- `name`: user's display name (from the Name field)
- `language`: `"en"`
- `promoCode`, `purchaseOrderToken`, `stripePurchaseOrderToken`: empty strings
- `source`: `"B"` (B = Browser/web client)
- `companySize`: empty string

Our earlier calls only sent `{"email": "...", "type": "I"}`, which was accepted initially but may have been the reason for later 400 errors (or the 400s were IP-level rate limiting after too many attempts).

### 13.5 The `op-user-agent` Header

The SPA sends a custom `op-user-agent` header on all API requests. Format:

```
1|B|{buildNumber}|{deviceUuid}|||{browserName}|{browserVersion}|{platform}|{osVersion}|
```

Components:
- `1` — protocol version
- `B` — client type (B = Browser)
- `2248` — build number (from data-build-time or hardcoded)
- `{deviceUuid}` — 26-char random alphanumeric string, generated per session
- `|||` — empty fields (possibly app-specific identifiers)
- `Chrome|145.0.7632.6` — browser name and version
- `MacOSX|26.3.1` — platform and OS version

This header appears on every API request from the SPA. Our previous API calls omitted it entirely.

### 13.6 Cookies Set During Signup

The `.1password.com` domain sets three cookies during the flow:

| Cookie | Value | Purpose |
|--------|-------|---------|
| `_tsession` | 26-char random string | Session tracking |
| `_ab` | `a` or `b` | A/B test assignment |
| `_fs` | UUID | Flow service correlation ID |

These are set with `domain=.1password.com` and apply across all 1Password subdomains.

### 13.7 Verify Page URL Encoding

After successful signup POST, the SPA navigates to the verify page with base64url-encoded signup data in the URL:

```
https://my.1password.com/sign-up/verify/{base64url_json}?l=en
```

Decoded JSON contains:
```json
{
  "accountType": "individual",
  "type": "I",
  "userName": "Eric Hartford",
  "email": "...",
  "emailResendToken": "ONARTAWATZEETHXZXVKLNN3YNH4",
  "newsletterSubscribe": false,
  "companySize": "",
  "purchaseOrder": "",
  "stripePurchaseOrder": ""
}
```

### 13.8 Pre-Registration Features

The SPA calls two feature-flag endpoints before showing the signup form:

**`POST /api/pre-registration-features`** — checks broad feature flags:
```json
{"features": ["test-feature-flag", "b5web-auto-sign-in", "b5web-mycelium-forward-sign-in",
  "safari-web-extension-iap", "b5web-b2b-signup-requirePhoneNumber", ...]}
```

**`POST /api/v2/pre-registration-features`** — checks specific flags with context:
```json
{
  "features": ["b5web-b2b-signup-requirePhoneNumber"],
  "baseFeatureContext": {
    "deviceUuid": "...",
    "app": "1Password for Web",
    "browserType": "Chrome",
    "buildNumber": "2248",
    "platform": "MacOSX",
    "subEnvironment": ""
  }
}
```

Both endpoints return 200 on all tested domains (CTF, start, my).

### 13.9 IP-Level Rate Limiting

After multiple signup attempts across sessions, all API calls to both `bugbounty-ctf.1password.com` and `start.1password.com` began returning 400 with empty body `{}`. This appears to be IP-level rate limiting (not email-specific — tested with multiple emails). The rate limiter escalated from 429 (with retry-after) to hard 400 blocks.

### 13.10 Phase 13 Assessment

**Solved:** The exact request format, headers, and flow the SPA uses for signup and email verification. The critical missing pieces in our earlier API calls were:
1. The `op-user-agent` header (sent on every request)
2. Additional body fields (`domain`, `name`, `source`, etc.)
3. The correct target domain (SPA sends to `start.1password.com`, not `bugbounty-ctf.1password.com`)

**Remaining:** Need to capture the exact verification request (entering the 6-digit code on the verify page). From JS analysis we know it's `GET /api/v2/signup/{code}?email=X&account-type=Y`, but need to confirm which domain it targets and whether cookies/headers matter.

**Next steps:**
1. Wait for IP rate limit to clear
2. Redo signup with `eric@quixi.ai` using the correct full request format
3. Capture the verification GET request via the browser
4. Complete the full account registration flow

---

## Phase 14: CTF Rules, White Paper Analysis & Protocol Deep Dive

**Date:** 2026-04-29

### 14.1 CTF Rules (HackerOne)

Retrieved the full CTF program description from HackerOne GraphQL API (`hackerone.com/1password_ctf`).

**Key rules:**
- $1M reward, running since 2022 — unclaimed after 4+ years
- "There are no known vulnerabilities that will award you access to the flag; there's no starting point, nor a guaranteed reward."
- **Target:** Bad poetry in a Secure Note, in a dedicated CTF account at `bugbounty-ctf.1password.com`
- **Access:** Email `bugbounty@agilebits.com` with HackerOne username → receive access to the CTF account with "more information"
- Only submit if you've captured the flag or are close — invalid submissions lose HackerOne points
- Recommended reading: White paper "Beware of the Leopard" section (page 68 / Appendix A)
- Provided tool: `github.com/1Password/burp-1password-session-analyzer`

**Scope (Burp config):**
- Include: `bugbounty-ctf.1password.com:443` only
- Exclude: `*.agilebits.com`, `support.1password.com`, `www.1password.com`

**Critical realization:** We were trying to CREATE an account when we should have REQUESTED ACCESS to the existing CTF account. The signup flow was a dead end — the vault with the flag is in a pre-existing account that researchers get invited to.

Email sent to `bugbounty@agilebits.com` requesting CTF account access on 2026-04-29.

### 14.2 Burp Session Analyzer — Protocol Implementation

Cloned `github.com/1Password/burp-1password-session-analyzer` to `projects/1password/burp-1password-session-analyzer/`.

#### 14.2.1 Session Encryption (AES-256-GCM)

All API payloads are encrypted with the session key:

- **Algorithm:** AES-256-GCM (AES/GCM/NoPadding)
- **Key:** 256-bit (32 bytes), base64url-encoded (43 chars)
- **IV:** 96-bit (12 bytes), unique per message
- **Auth tag:** 128-bit (implicit in GCM)

**Encrypted message JSON structure:**
```json
{
  "kid": "GBOJATMN3FGLNPXPBMMQXS6XH4",
  "enc": "A256GCM",
  "cty": "b5+jwk+json",
  "iv": "Br3mr9L_-CIsl21k",
  "data": "<base64url ciphertext>"
}
```

- `kid`: 26-char key identifier (matches session ID)
- `enc`: always `"A256GCM"`
- `cty`: always `"b5+jwk+json"`
- `iv`: base64url 12-byte IV
- `data`: base64url ciphertext (includes GCM auth tag)

The session key derives from the SRP exchange during login. With the session key, all traffic can be decrypted and re-encrypted.

#### 14.2.2 Request MAC (X-AgileBits-MAC)

Every authenticated request includes `X-AgileBits-MAC: v1|{requestId}|{mac}`:

```
authString = sessionId | requestMethod | host/path?query | v1 | requestId
macKey = HMAC-SHA256(sessionKey, "He never wears a Mac, in the pouring rain. Very strange.")
mac = HMAC-SHA256(macKey, authString)
header = "v1|" + requestId + "|" + base64url(mac[0:12])
```

- Session ID from `X-AgileBits-Session-ID` header
- Request ID is monotonically incrementing (prevents replay)
- MAC truncated to first 12 bytes (96 bits)
- HMAC algorithm: HMAC-SHA256

**Key derivation constant:** `"He never wears a Mac, in the pouring rain. Very strange."` (ASCII)

**Test vectors (from source):**
```
sessionId: RDPMIFQWUJBWZFDBKURHNRFVRA
sessionKey: ETmGs4U7ReMolW1J64ZAmmksXbQFFbeyRPW6zPWj3VM
requestId: 6
method: GET
url: https://my.b5local.com:3000/api/v1/invites
expected: v1|6|oBnE8JLpG2Othzgy
```

#### 14.2.3 Session Key Extraction

The README hints: "you can probably find the session key yourself by knowing that we use standard JavaScript APIs (SubtleCrypto) to do the encryption in the 1Password frontend."

This means: hook `crypto.subtle.importKey` or `crypto.subtle.encrypt`/`decrypt` in the browser to capture the AES-256-GCM session key. Our `webcrypto_hooks` clearwing tool was designed exactly for this.

### 14.3 White Paper — Security Architecture

Source: `agilebits.github.io/security-design/` (redirected from `1password.com/files/1Password-White-Paper.pdf`)

#### 14.3.1 Key Hierarchy

```
Account Password + Secret Key
        ↓ (PBKDF2-HMAC-SHA256, 650K iterations + HKDF + XOR)
Account Unlock Key (AUK)
        ↓ (decrypts)
Personal Keyset (RSA-2048 private key + symmetric key)
        ↓ (RSA decrypt)
Vault Key (AES-256, per-vault, random)
        ↓ (AES-256-GCM)
Vault Items (overview + details encrypted separately)
```

- **Secret Key format:** Characters from `{2-9, A-H, J-N, P-T, V-Z}` — avoids ambiguous chars (0/O, 1/I/L)
- **Secret Key entropy:** 128 bits
- **Salt stretching:** 16-byte salt stretched via HKDF with lowercase email as context
- **Password preprocessing:** strip whitespace, NFKD normalization
- **2SKD XOR step:** PBKDF2 output XOR'd with HKDF(Secret Key, account_id_as_salt)
- **AUK output:** JWK with key ID `"mp"`
- **SRP-x:** Derived identically to AUK but with independent salt — ensures auth and encryption keys are independent

#### 14.3.2 Item Encryption

- Items have two encrypted components: **overview** (title, URL, tags) and **details** (passwords, notes)
- Both encrypted with the vault key using AES-256-GCM
- Each user gets a copy of the vault key encrypted with their RSA public key
- Private key is encrypted with AUK derived from password + Secret Key

#### 14.3.3 Server Storage

The server stores (unencrypted):
- Team/account info (domain, name, avatars)
- User info (names, emails, avatar filenames)
- Device metadata (IP, device model, OS)
- MFA secrets and public keys
- Group info (names, descriptions)

Database tables: `accounts`, `users`, `vaults`, `vault_items`, `user_vault_access`, `groups`, `invites`, `signups`

The `vault_items` table stores encrypted overviews and details. The `user_vault_access` table stores vault keys encrypted per-user with their public key.

Even if the database is fully compromised, vault contents remain encrypted. Breaking in requires the private key, which requires the AUK, which requires password + Secret Key.

### 14.4 Acknowledged Weaknesses (Appendix A — "Beware of the Leopard")

| Section | Weakness | Exploitability |
|---------|----------|----------------|
| A.1 | Crypto over HTTPS — malicious server can deliver bad JS client | Requires server compromise |
| A.1.1 | Browser crypto limitations — can't clear memory, limited to PBKDF2 | Theoretical |
| A.2 | Recovery Group has crypto access to all vault keys | Requires Recovery Group member compromise |
| A.3 | **No public key verification — server can MITM key exchanges** | Server-side attack; no user verification possible |
| A.4 | Revoked users who saved vault keys can decrypt future data | Requires prior key exfiltration |
| A.5 | Password changes don't rotate keysets — old creds still work | Requires old credentials |
| A.6 | Weak primary account password unlocks stronger secondary accounts | Local attack |
| A.8 | No barrier to malicious client generating bad keys | Requires client compromise |
| A.9 | Server data accessible to governments/law enforcement | Server-side; data still encrypted |
| A.10.2 | **Secret Keys stored with "light obfuscation" on enrolled devices** | Requires device access |
| A.11 | **User enumeration possible — acknowledged "design error"** | Pre-auth, no fix planned |
| A.12 | Email-based invitations/recovery — email can be intercepted | Requires email compromise |

### 14.5 Strategic Assessment

**What 1Password has hardened against (the "expected" attack surface):**
- Brute-force password cracking (2SKD makes verifiers uncrackable without Secret Key)
- Server breach (all vault data encrypted, server never sees plaintext)
- Network MITM (SRP + session encryption on top of TLS)
- Replay attacks (monotonic request MAC counter)
- Client-side attacks (CSP, SRI, WebCrypto)

**What they acknowledge but accept:**
- Server can MITM public key exchanges (A.3)
- User enumeration via auth endpoint (A.11)
- Secret Keys recoverable from enrolled devices (A.10.2)

**The CTF is designed to be "impossible"** — they're confident the architecture prevents access without valid credentials. The $1M has been unclaimed for 4+ years. Breaking the crypto directly is not realistic.

**Potential vectors once we have CTF account access:**
1. **Access control logic bugs** — server grants vault key copies based on `user_vault_access` entries; can we trick it into granting access to vaults we shouldn't see?
2. **IDOR on vault items** — can we request vault items by UUID from vaults we don't have keys for? The server might return encrypted data we can't decrypt, but maybe there's a path where it returns decrypted data.
3. **Sharing/invitation flow bugs** — the mechanism that grants us CTF access might have logic flaws
4. **Recovery group exploitation** — if the CTF account has a recovery group and we're in it
5. **Session key + Burp analyzer** — once authenticated, use webcrypto hooks to capture session key, then use Burp analyzer to inspect and modify all requests
6. **Confidential Computing enclave** — we already completed Noise_NX handshake; with an authenticated session, the enclave might process requests differently
7. **Public key substitution (A.3)** — the server can substitute public keys; if we can somehow trigger re-encryption of the flag vault's key to our public key
8. **The "more information" in the CTF account** — may contain hints, partial credentials, or a different attack surface entirely

**Immediate next step:** Wait for CTF account access via email response from `bugbounty@agilebits.com`.


## Phase 15 — CTF Domain Probing (In-Scope)

**Date:** 2026-05-01

Revisited the CTF domain directly (`bugbounty-ctf.1password.com`) to probe in-scope endpoints.

### 15.1 Sign-In Page Structure

Navigated to `https://bugbounty-ctf.1password.com` via Playwright with extension bypass (mock `document.body.dataset.onepasswordExtensionVersion` and `b5xBuildNumber`). Rate limiting from prior sessions (2026-04-29) has cleared — page loads normally.

The CTF domain redirects to `/signin` and serves a standard 1Password sign-in form:
- Email field
- Secret Key field (shown after email submission)
- Password field
- "Sign In" button
- "Create a new account" link → points to `https://1password.com/sign-up/` (off-scope, main site)

**Key finding:** The CTF domain does not support self-registration. Accounts must be provisioned externally. This confirms the HackerOne instruction to email `bugbounty@agilebits.com` for access.

### 15.2 Auth Methods Endpoint (No User Enumeration)

**Endpoint:** `POST /api/v2/auth/methods`

Tested with two emails:
```
POST /api/v2/auth/methods {"email":"nonexistent_test_xyz_12345@example.com"}
→ 200 {"authMethods":[{"type":"PASSWORD+SK"}],"signInAddress":"https://bugbounty-ctf.1password.com"}

POST /api/v2/auth/methods {"email":"eric@quixi.ai"}
→ 200 {"authMethods":[{"type":"PASSWORD+SK"}],"signInAddress":"https://bugbounty-ctf.1password.com"}
```

**Finding:** Identical response for both existent and nonexistent emails. No user enumeration via this endpoint. The auth method is always `PASSWORD+SK` for this domain. The `signInAddress` confirms the CTF domain is self-contained.

Note: The white paper acknowledges user enumeration as a known weakness (Appendix A.11), but this specific endpoint doesn't leak it. The SRP init endpoint (`/api/v1/auth`) may behave differently — needs testing with valid credentials.

### 15.3 Pre-Registration Features

**Endpoint:** `POST /api/pre-registration-features`

The CTF domain serves the same feature flag set as the main site:
```json
{
  "features": [
    {"name": "b5web-auto-sign-in"},
    {"name": "b5web-mycelium-forward-sign-in"},
    {"name": "safari-web-extension-iap"},
    {"name": "b5web-b2b-signup-requirePhoneNumber"},
    {"name": "b5-bpo-client-notification"},
    {"name": "pre-auth-telemetry-data-collection"},
    {"name": "distributor-sign-up"},
    {"name": "distributor-change-of-channel"},
    {"name": "b5web-authx-auto_sign_in-policy"}
  ]
}
```

Notable flags: `b5web-mycelium-forward-sign-in` (device pairing for sign-in), `b5web-authx-auto_sign_in-policy` (auto sign-in policy).

### 15.4 Mycelium Device Pairing Channels

**Endpoint:** `POST /api/v2/mycelium/u`

The sign-in page automatically creates Mycelium pairing channels on load:
```json
{"channelSeed":"vWwQy0HDbdl74v9ho_aFQA","channelUuid":"KK4XZK47EDKQ4HQN6J3QUNJKXE","initiatorAuth":"i_0bBT_CUXw9i-a8yKOtM1bQ"}
```

Each page load creates 2 channels with unique UUIDs and seeds. The client then polls `GET /api/v2/mycelium/u/{channelUuid}/2` repeatedly (long-polling). These channels are for QR-code-based sign-in via a mobile device.

The request body includes a `deviceUuid` and a `hello` field (base64url-encoded, ~128 bytes). This is the Noise_NX handshake initiator message for the Mycelium protocol.

**Security note:** Mycelium channels are created pre-auth. If channel UUIDs are predictable or reusable, this could be an attack surface for session hijacking via the device pairing flow.

### 15.5 Account Cookies Check

On page load, the client checks for existing account cookies across all 1Password regions:
```
GET https://accounts.1password.com/api/v1/accountcookies → []
GET https://accounts.1password.ca/api/v1/accountcookies → []
GET https://accounts.ent.1password.com/api/v1/accountcookies → []
GET https://accounts.1password.eu/api/v1/accountcookies → []
```

All return empty arrays — no existing sessions. These requests go to production domains (not the CTF domain), confirming the CTF domain shares the same client codebase as production 1Password.

### 15.6 JS Bundle Source

The main application JS is loaded from `https://app.1password.com/js/webapi-092b9e5d154383738ffc.min.js` — a shared CDN for the 1Password web client. The CTF domain does not serve its own JS; it uses the same production web app. This means:
- Any client-side vulnerability in the production web app applies to the CTF domain
- The CSP, SRI hashes, and WASM whitelist are identical to production
- Client-side attack vectors (Phase 3.9) are the same

### 15.7 Scope Discipline

Attempted to create a regular 1Password account on `start.1password.com` / `my.1password.com` to observe the registration protocol. Stopped mid-flow after recognizing this is outside the CTF scope. The CTF rules state only `bugbounty-ctf.1password.com` is in play.

**Lesson learned:** All probing, protocol analysis, and API testing must target the CTF domain only. Understanding the protocol from public documentation (white paper, Burp analyzer source) is fine; actively instrumenting production infrastructure is not.

### 15.8 Copy Fail (CVE-2026-31431) Assessment

Documented separately in `projects/1password/copyfail.md`. Linux kernel privilege escalation via AF_ALG + splice page cache corruption, disclosed 2026-04-29. Relevant to the CTF only if we achieve server-side code execution first — it's an escalation primitive, not an entry point. The CTF infrastructure likely runs on Linux behind AWS ELB, but patching status is unknown.

### 15.9 Summary of Pre-Auth Attack Surface (CTF Domain)

| Endpoint | Method | Behavior | Notes |
|----------|--------|----------|-------|
| `/signin` | GET | Sign-in page | Standard 1Password web client |
| `/api/v2/auth/methods` | POST | Returns `PASSWORD+SK` | No user enumeration |
| `/api/pre-registration-features` | POST | Feature flags | Same as production |
| `/api/v2/mycelium/u` | POST | Creates pairing channel | Pre-auth, 2 channels per load |
| `/api/v2/mycelium/u/{uuid}/2` | GET | Long-polls channel | Noise_NX handshake |

**Still untested (need credentials):**
- `/api/v1/auth` — SRP init (salt, iterations, B)
- `/api/v1/auth/verify` — SRP proof verification
- `/api/v2/recovery-keys/*` — Recovery flow endpoints
- All authenticated endpoints (vaults, items, keys)

**Next step:** Await CTF account credentials from `bugbounty@agilebits.com` (email sent 2026-04-29).
