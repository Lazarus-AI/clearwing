# 1Password $1M CTF — Clearwing Runbook

## 1. CTF Goals

### Target

A secure note containing "bad poetry" stored in a dedicated 1Password Bug Bounty
CTF account at `bugbounty-ctf.1password.com`. The note is protected by the full
1Password security stack: SRP authentication, two-secret key derivation (2SKD),
AES-256-GCM vault encryption, and TLS transport.

### Win condition

Recover the plaintext content of the secure note and submit the steps used to
capture it via HackerOne.

### Constraints

- No known vulnerabilities or starting point — this is a live, hardened production
  system with a purpose-built CTF account.
- No phishing, malware, or compromise of real 1Password member accounts.
- Only the `bugbounty-ctf.1password.com` scope is in play.
- Partial theories and collaboration are welcome via `bugbounty@agilebits.com`.

### What we need to break

At least one of the following must fail for the flag to be recoverable:

| Layer | Protection | What a break looks like |
|-------|-----------|------------------------|
| **Authentication** | SRP-6a + 2SKD (account password x Secret Key) | Bypass or forge SRP verifier; recover both secrets; exploit protocol flaw |
| **Key derivation** | PBKDF2-HMAC-SHA256 (100k+ iterations) + 128-bit Secret Key XOR | Reduce keyspace; side-channel leak of derived key; skip KDF entirely |
| **Vault encryption** | AES-256-GCM per-item, keys wrapped by personal keyset | Recover AUK or vault key; forge AEAD tag; exploit key hierarchy |
| **Transport** | TLS 1.3 + HSTS | MITM; downgrade; certificate substitution |
| **Server-side** | Access control, encrypted blob storage | Server-side bug (IDOR, authz bypass, API logic flaw) exposes encrypted or plaintext vault data |
| **Key distribution** | Public-key encryption (no user-to-user verification) | MITM on public key exchange; server substitutes attacker key |
| **Web client** | JavaScript delivered over TLS | Tamper with client delivery; exploit browser-side weakness; XSS in client app |

The white paper's "Beware of the Leopard" appendix (Appendix A) explicitly
acknowledges weaknesses in several of these layers. Those are the most
productive starting points.


## 2. Clearwing Toolchain

All tools referenced in the runbook below. Organized by attack domain.

### 2.1 Reconnaissance & Browser

| Tool | Module | Purpose |
|------|--------|---------|
| `browser_navigate` | `recon/browser_tools` | Load pages, extract JS bundles |
| `browser_execute_js` | `recon/browser_tools` | Run arbitrary JS in page context |
| `browser_get_html` | `recon/browser_tools` | Extract full page source |
| `browser_get_cookies` | `recon/browser_tools` | Extract session tokens |
| `browser_fill` / `browser_click` | `recon/browser_tools` | Automate login flow |
| `proxy_request` | `recon/proxy_tools` | Crafted HTTP requests to API endpoints |
| `proxy_replay` | `recon/proxy_tools` | Replay captured requests with modifications |
| `scan_ports` | `scan/scanner_tools` | Port enumeration |
| `detect_services` | `scan/scanner_tools` | Service fingerprinting |
| `scan_vulnerabilities` | `scan/scanner_tools` | NVD cross-reference |
| `search_cves` | `meta/reporting_tools` | CVE database search |

### 2.2 TLS & Transport

| Tool | Module | Purpose |
|------|--------|---------|
| `scan_tls_config` | `scan/tls_tools` | Protocol version, cipher suite, certificate chain |
| `enumerate_cipher_suites` | `scan/tls_tools` | Full cipher suite enumeration with weakness flags |
| `test_tls_downgrade` | `scan/tls_tools` | TLS 1.0/1.1/SSL3 downgrade and POODLE/DROWN/FREAK checks |
| `inspect_certificate` | `scan/tls_tools` | Deep cert analysis: key strength, CT logs, pinning |
| `mitm_start` | `recon/mitm_proxy` | Start intercepting TLS proxy with dynamic certs |
| `mitm_set_intercept_rule` | `recon/mitm_proxy` | Drop, delay, or modify requests in flight |
| `mitm_get_decrypted_traffic` | `recon/mitm_proxy` | Query decrypted API traffic log |
| `mitm_inject_response` | `recon/mitm_proxy` | Serve tampered JS bundles or fake public keys |

### 2.3 SRP Protocol

| Tool | Module | Purpose |
|------|--------|---------|
| `srp_handshake` | `crypto/srp_tools` | Full SRP-6a auth with all intermediate values |
| `srp_fuzz_parameters` | `crypto/srp_tools` | Zero-key attacks (A=0, A=N, A=2N), malformed proofs |
| `srp_extract_verifier_info` | `crypto/srp_tools` | Extract salt, iterations, group params; username enumeration |
| `srp_timing_attack` | `crypto/srp_tools` | Statistical timing analysis of auth stages |

### 2.4 Key Derivation & 2SKD

| Tool | Module | Purpose |
|------|--------|---------|
| `analyze_kdf_parameters` | `crypto/kdf_tools` | Extract and assess KDF config vs OWASP minimums |
| `benchmark_kdf_cracking` | `crypto/kdf_tools` | Cracking cost estimate at GPU tiers |
| `test_2skd_implementation` | `crypto/kdf_tools` | Verify Secret Key XOR, AUK/SRP-x split correctness |
| `kdf_oracle_test` | `crypto/kdf_tools` | Timing/response oracle leaks in KDF validation |
| `analyze_2skd_entropy` | `crypto/credential_tools` | Combined keyspace calculation (password x Secret Key) |
| `test_secret_key_validation` | `crypto/credential_tools` | Factor separation: does the server distinguish wrong-password from wrong-key? |
| `enumerate_secret_key_format` | `crypto/credential_tools` | Secret Key structure, entropy, predictable components |
| `offline_crack_setup` | `crypto/credential_tools` | Generate hashcat/john commands for captured material |

### 2.5 Vault Encryption

| Tool | Module | Purpose |
|------|--------|---------|
| `parse_vault_blob` | `crypto/vault_tools` | Parse encrypted item structure (IV, tag, key ID) |
| `analyze_key_hierarchy` | `crypto/vault_tools` | Map AUK -> keyset -> vault key -> item key chain |
| `test_aead_integrity` | `crypto/vault_tools` | Bit-flip, truncation, tag substitution attacks |
| `key_wrap_analysis` | `crypto/vault_tools` | AES-KW / RSA-OAEP wrapping analysis, padding oracle test |

### 2.6 Timing & Side Channels

| Tool | Module | Purpose |
|------|--------|---------|
| `timing_probe` | `crypto/timing_tools` | Nanosecond-precision request timing with statistics |
| `timing_compare` | `crypto/timing_tools` | Welch's t-test between two request distributions |
| `timing_bitwise_probe` | `crypto/timing_tools` | Byte-at-a-time timing attack |

### 2.7 WebCrypto & Auth Flow Capture

| Tool | Module | Purpose |
|------|--------|---------|
| `install_webcrypto_hooks` | `recon/webcrypto_hooks` | Instrument all SubtleCrypto methods |
| `get_webcrypto_log` | `recon/webcrypto_hooks` | Retrieve captured crypto operations |
| `extract_srp_values` | `recon/webcrypto_hooks` | Parse SRP handshake from crypto log |
| `extract_key_hierarchy` | `recon/webcrypto_hooks` | Reconstruct key derivation chain from crypto log |
| `start_auth_recording` | `recon/auth_recorder` | Unified capture: browser + proxy + crypto + timing |
| `stop_auth_recording` | `recon/auth_recorder` | Stop recording and return AuthFlowRecord |
| `diff_auth_flows` | `recon/auth_recorder` | Compare two auth flows for differential analysis |

### 2.8 Source Analysis & Exploit

| Tool | Module | Purpose |
|------|--------|---------|
| `hunt_source_code` | `meta/sourcehunt_tools` | Clone, rank, and hunt public repos for crypto bugs |
| `create_custom_tool` | `ops/dynamic_tool_creator` | Write custom Python attack tools at runtime |
| `kali_setup` / `kali_execute` | `ops/kali_docker_tool` | Full Kali toolchain (hashcat, nmap, testssl.sh) |
| `search_exploit_db` | `exploit/exploit_search` | Exploit-DB and NVD search |

### 2.9 Knowledge, CVE Database & Reporting

| Tool | Module | Purpose |
|------|--------|---------|
| `cve_db_update` | `data/cve_tools` | Download and index NVD CVE List V5 into local SQLite (346k+ CVEs) |
| `cve_search` | `data/cve_tools` | Full-text search with CVSS, date, and CWE filters |
| `cve_lookup` | `data/cve_tools` | Deep dive on a specific CVE ID |
| `query_knowledge_graph` | `data/knowledge_tools` | Query the crypto-aware knowledge graph |
| `store_knowledge` / `search_knowledge` | `data/memory_tools` | Persist and recall findings across sessions |
| `generate_report` / `save_report` | `meta/reporting_tools` | Compile HackerOne submission |
| `load_skills` | `ops/skill_tools` | Load crypto attack methodology playbooks |

### 2.10 Crypto Skill Pack

Pre-built attack methodology playbooks in `clearwing/core/skills/crypto/`:

| Skill | Coverage |
|-------|----------|
| `srp_attacks` | Zero-key, parameter manipulation, verifier theft, session key recovery |
| `kdf_analysis` | OWASP compliance, iteration count assessment, 2SKD verification |
| `timing_attacks` | Network timing methodology, drift cancellation, statistical rigor |
| `aead_misuse` | AES-GCM nonce reuse, tag forgery, associated data omission |
| `key_hierarchy` | Key wrapping attacks, derivation chain analysis, padding oracles |
| `padding_oracle` | CBC padding oracle exploitation methodology |
| `tls_assessment` | TLS configuration testing, downgrade detection, cert analysis |


## 3. Runbook

Step-by-step procedures for the CTF engagement. Each step specifies the tools to
use, what to look for, and decision branches based on results.

### Phase 1: Reconnaissance

Goal: map the attack surface before touching any crypto.

#### Step 1.1 — Infrastructure Scan

```
scan_ports(target="bugbounty-ctf.1password.com")
detect_services(target="bugbounty-ctf.1password.com")
```

**Look for:** Open ports beyond 443. Non-standard services. Server software
versions with known CVEs.

**If unusual ports found:** Run `scan_vulnerabilities` and `search_cves` against
detected services. Document in knowledge graph.

**If only 443:** Expected. Move to TLS audit.

#### Step 1.2 — TLS Configuration Audit

```
scan_tls_config(target="bugbounty-ctf.1password.com", port=443)
enumerate_cipher_suites(target="bugbounty-ctf.1password.com", port=443)
test_tls_downgrade(target="bugbounty-ctf.1password.com", port=443)
inspect_certificate(target="bugbounty-ctf.1password.com", port=443)
```

**Look for:**
- TLS 1.0/1.1 still accepted (downgrade path)
- Weak cipher suites (RC4, DES, export-grade, NULL)
- Certificate chain issues (weak key, missing intermediate, expired)
- Missing HSTS or short max-age
- OCSP stapling disabled

**If downgrade possible:** Flag as finding. Test POODLE/BEAST applicability via
Kali: `kali_execute(command="testssl.sh --vulnerable bugbounty-ctf.1password.com")`.

**If TLS is clean:** Expected for 1Password. Document and move on.

#### Step 1.3 — Web Client Extraction

```
browser_navigate(url="https://bugbounty-ctf.1password.com")
browser_get_html()
```

**Extract:**
- All JavaScript bundle URLs (look for webpack chunks, main bundle)
- API endpoint base paths
- SRP library identification (look for `srp`, `bigint`, modular exponentiation)
- Content Security Policy headers
- Service worker registrations
- Subresource Integrity (SRI) hashes

**Save the full JS bundle** — it contains the client-side crypto implementation.
This is the primary artifact for Phase 2.

#### Step 1.4 — API Enumeration

```
proxy_request(url="https://bugbounty-ctf.1password.com/api/v1/auth", method="POST",
              body={"email": "test@example.com"})
proxy_request(url="https://bugbounty-ctf.1password.com/api/v2/auth", method="POST",
              body={"email": "test@example.com"})
```

Probe systematically:
- `/api/v1/auth` — SRP init endpoint
- `/api/v1/auth/verify` — SRP verify endpoint
- `/api/v1/auth/enroll` — enrollment (key generation)
- `/api/v1/vaults` — vault listing
- `/api/v1/items` — item access
- `/api/v2/*` — check for API version differences
- `/.well-known/` — OpenID, security.txt, change-password

**Look for:**
- Endpoints that respond without authentication
- Verbose error messages that leak internal structure
- Rate limiting behavior (or lack thereof)
- CORS misconfiguration
- Different behavior between API versions

#### Step 1.5 — Public Source Analysis

```
hunt_source_code(target="https://github.com/1Password", specialist="crypto_primitive")
```

Repositories to prioritize:
- `srp` implementations in any language
- Client SDK code (browser, CLI)
- Key derivation libraries
- Anything referencing `2SKD`, `Secret Key`, or `Account Unlock Key`

**Look for:** Timing-unsafe comparisons on secrets (`memcmp`), nonce reuse,
missing point validation, key material in logs.

#### Step 1.6 — CVE / Exploit Search

```
cve_db_update(zip_path="/path/to/cvelistV5-main.zip")
cve_search(query="1password OR agilebits", max_results=25)
cve_search(query="SRP authentication bypass", min_cvss=5.0)
cve_search(query="PBKDF2 side channel OR timing", min_cvss=5.0)
cve_search(query="AES-GCM nonce reuse", min_cvss=5.0)
cve_search(query="WebCrypto", min_cvss=5.0)
search_exploit_db(query="1password")
```

The local CVE database (346k+ CVEs with FTS5 search) enables fast, comprehensive
searches without rate limits. Use `cve_lookup(cve_id="CVE-XXXX-YYYY")` for deep
dives on specific CVEs. Low probability of direct hits against 1Password, but
establishes baseline awareness of known weakness classes in SRP, PBKDF2, and
AES-GCM.


### Phase 2: Protocol Analysis

Goal: understand and instrument the authentication protocol. Capture every
intermediate value.

#### Step 2.1 — Record a Baseline Auth Flow

Start the MITM proxy, install WebCrypto hooks, then record a full auth attempt:

```
mitm_start(listen_port=8443, upstream_target="bugbounty-ctf.1password.com")
start_auth_recording(target="https://bugbounty-ctf.1password.com",
                     credentials={"email": "...", "password": "...", "secret_key": "..."},
                     enable_webcrypto=True, enable_proxy=True)
```

Wait for login to complete (or fail), then:

```
stop_auth_recording()
```

**The AuthFlowRecord captures:**
- Every HTTP request/response in the auth sequence, with decrypted bodies
- Every `crypto.subtle` call (deriveBits, importKey, encrypt, decrypt) with
  arguments and timing
- SRP handshake values: salt, iterations, A, B, M1, M2
- KDF parameters: algorithm, iteration count, salt, output length
- Session tokens and cookies produced

**This is the most important artifact in the engagement.** All subsequent
analysis references it.

#### Step 2.2 — Extract and Validate SRP Parameters

From the captured flow, or directly:

```
srp_extract_verifier_info(target="https://bugbounty-ctf.1password.com/api/v1/auth",
                          username="ctf-account-email")
```

**Record:**
- Salt (hex)
- Iteration count
- SRP group (N, g) — which RFC group?
- Algorithm (PBKDF2-HMAC-SHA256 expected)
- Server's ephemeral B value

```
analyze_kdf_parameters(target="bugbounty-ctf.1password.com",
                       algorithm="PBKDF2-HMAC-SHA256",
                       iterations=<from_above>,
                       salt_hex="<from_above>")
```

**Decision:** If iterations < OWASP minimum (600,000 for SHA-256), flag as
weakness. If salt is static or predictable, flag. Otherwise, KDF is likely
correctly parameterized.

#### Step 2.3 — Analyze 2SKD Strength

```
analyze_2skd_entropy(password_entropy_bits=40.0, secret_key_bits=128,
                     iterations=<from_above>)
```

**Expected result:** Combined entropy ~168 bits. Brute force infeasible at any
GPU budget. This establishes the baseline — the tools below test whether the
*implementation* matches this theoretical strength.

```
enumerate_secret_key_format(target="https://bugbounty-ctf.1password.com",
                            username="ctf-account-email")
```

**Look for:**
- Predictable prefix (A3 is the version — is it always A3?)
- Reduced charset (33 chars, not full base-36)
- Sequential or time-based components
- Server-side leakage of format info in error messages

#### Step 2.4 — Test Factor Separation (Critical)

This is the highest-value test in the credential analysis suite. If the server
distinguishes "wrong password" from "wrong Secret Key," each factor can be
attacked independently — collapsing 168 bits to max(40, 128).

```
test_secret_key_validation(
    target="https://bugbounty-ctf.1password.com/api/v1/auth",
    username="ctf-account-email",
    password="known-password",
    secret_key="A3-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX",
    samples=50,
    warmup=10,
    outlier_method="iqr"
)
```

**Separation signals to watch:**
- **Timing**: Statistically significant difference (Welch's t-test p < 0.05,
  Cohen's d > 0.5) between wrong-password and wrong-key response times
- **Response body**: Different error messages or error codes
- **HTTP status**: Different status codes for the two failure modes

**If factor separation detected:** This is a critical finding. File immediately.
The server must validate both factors simultaneously — any separation breaks
the 2SKD security model. Proceed to Step 3.6 for independent factor attacks.

**If no separation:** Good implementation. Move to SRP protocol attacks.

#### Step 2.5 — Differential Auth Flow Analysis

Record a second auth flow with a deliberate change (wrong password):

```
start_auth_recording(target="https://bugbounty-ctf.1password.com",
                     credentials={"email": "...", "password": "WRONG", "secret_key": "..."},
                     enable_webcrypto=True, enable_proxy=True)
# ... wait for failure ...
stop_auth_recording()
```

Then compare:

```
diff_auth_flows(flow_a="<baseline_record>", flow_b="<wrong_password_record>")
```

**Look for:**
- Which step diverges first? (Should be SRP verify, not init)
- Does the server compute differently for wrong vs. right password?
- Are there extra round trips in one flow but not the other?
- Do client-side crypto operations differ? (If so, the client may be leaking
  information about which factor failed)

Repeat with wrong Secret Key, valid password — compare all three.

#### Step 2.6 — WebCrypto Deep Inspection

If not already captured via auth recording:

```
install_webcrypto_hooks(tab_name="1password-ctf")
browser_navigate(url="https://bugbounty-ctf.1password.com")
# Perform login
get_webcrypto_log(tab_name="1password-ctf")
extract_srp_values(tab_name="1password-ctf")
extract_key_hierarchy(tab_name="1password-ctf")
```

**Map the complete key chain:**
1. Password + Secret Key -> PBKDF2 -> 64-byte derived key
2. Derived key split: first 32 bytes = AUK, last 32 bytes = SRP-x
3. AUK decrypts personal keyset (AES-GCM)
4. Keyset contains vault symmetric keys (AES-KW wrapped)
5. Vault keys decrypt individual items (AES-256-GCM)

**Look for:**
- Is the Secret Key XOR applied *after* PBKDF2? (Correct)
- Is the split at exactly byte 32? (Verify)
- Are there any intermediate keys stored in localStorage/IndexedDB?
- Does the client cache derived keys across sessions?
- Any `exportKey` calls that expose raw key material?


### Phase 3: Attack Execution

Goal: systematically test each attack class.

**Critical constraint discovered in Phase 1:** All API traffic beyond the SRP
handshake is encrypted with the session key and authenticated via
`X-AgileBits-MAC`. Standard HTTP fuzzing tools cannot send valid requests.
This divides attacks into two tiers:

- **Pre-auth attacks** (Steps 3.1–3.5): Can be executed without credentials.
  Target the SRP handshake, timing side channels, and the recovery flow.
- **Authenticated attacks** (Steps 3.6–3.9): Require either a valid session
  (from a test account or a successful pre-auth exploit) or use the
  1Password Burp plugin to encrypt/decrypt session traffic. These attack the
  vault encryption, key hierarchy, and server-side authorization.

---

#### Pre-Auth Attacks

#### Step 3.1 — SRP Zero-Key Attack

The classic SRP implementation bug. If the server doesn't validate `A % N != 0`,
the shared secret becomes deterministic regardless of the password.

```
load_skills(skill_name="srp_attacks")
srp_fuzz_parameters(
    target="https://bugbounty-ctf.1password.com/api/v1/auth",
    username="ctf-account-email",
    test_vectors="all"
)
```

**Vectors tested:** A=0, A=N, A=2N, A=kN, truncated proofs, malformed values.

**If the server accepts A=0 and returns M2:**
1. Compute `K = H(0)` — the session key is now known
2. Use K to encrypt/MAC requests and access the authenticated API
3. Retrieve encrypted vault data via the session
4. Vault data is still encrypted by AUK, but we have a valid session —
   proceed to key hierarchy analysis (Step 3.7)

**Expected result:** Server rejects. The public SRP library (`1Password/srp`)
correctly validates A in `IsPublicValid()`: rejects A=0 via `IsZero()` and
A=kN via `Reduce(A).IsZero()`. But the production server may use a different
implementation, so always test.

#### Step 3.2 — SRP Timing Analysis

```
srp_timing_attack(
    target="https://bugbounty-ctf.1password.com/api/v1/auth",
    username="ctf-account-email",
    samples=100,
    warmup=10
)
```

**Look for timing differences in:**
- Username lookup (valid vs. invalid email) — user enumeration
- M1 proof validation (random M1 vs. zero M1)

Also run the general-purpose timing tools against the unauthenticated
`/api/v2/auth` endpoint:

```
timing_compare(
    target="https://bugbounty-ctf.1password.com",
    method_a="POST", path_a="/api/v2/auth",
    body_a='{"email":"valid@example.com"}',
    label_a="valid_email",
    method_b="POST", path_b="/api/v2/auth",
    body_b='{"email":"nonexistent-user-12345@example.com"}',
    label_b="invalid_email",
    samples=100
)
```

**Note:** Step 1.4 already showed that auth endpoints return identical `401 {}`
for all emails, which is a good sign. But timing differences can exist even
when response bodies are identical.

**If timing leak found:** Quantify with Cohen's d. If d > 0.8 (large effect),
this enables user enumeration. Use `timing_bitwise_probe` to attempt
byte-at-a-time recovery if the leak correlates with specific input bytes.

#### Step 3.3 — KDF Oracle Testing

```
kdf_oracle_test(
    target="https://bugbounty-ctf.1password.com/api/v1/auth",
    username="ctf-account-email",
    samples=50
)
```

**Tests whether the server leaks whether the KDF output was "close" to correct.**
A properly implemented server should be indistinguishable regardless of how wrong
the derived key is.

#### Step 3.4 — Factor Separation (Pre-Auth via SRP)

```
test_secret_key_validation(
    target="https://bugbounty-ctf.1password.com/api/v1/auth",
    username="ctf-account-email",
    password="known-password",
    secret_key="A3-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX",
    samples=50,
    warmup=10,
    outlier_method="iqr"
)
```

This sends SRP verify requests with wrong-password vs. wrong-key derived
values. **Does not require a valid session** — it operates at the SRP
handshake level, which is pre-auth.

**If factor separation detected:** Critical finding. See Step 3.9.

#### Step 3.5 — Recovery Key Flow Exploitation

**This is the highest-value pre-auth attack surface identified in Phase 1.**
The white paper (Appendix A.4) acknowledges recovery groups as an expanded
attack surface. We found 10+ recovery endpoints in Step 1.4.

```
proxy_request(url="https://bugbounty-ctf.1password.com/api/v2/recovery-keys/session/new",
              method="POST", body={"email": "ctf-account@example.com"})
```

**Probe the full recovery flow:**

1. `/api/v2/recovery-keys/session/new` — can we start a recovery session
   without proper authorization? What parameters does it accept?
2. `/api/v2/recovery-keys/session/identity-verification/email/start` — does
   this trigger an email? Can we intercept or predict the verification code?
3. `/api/v2/recovery-keys/session/identity-verification/email/submit` — is
   the verification code brute-forceable? (No rate limiting was observed in
   Step 1.4)
4. `/api/v2/recovery-keys/session/material` — if we can reach this endpoint,
   does it return key material that could recover the account?
5. `/api/v2/recovery-keys/session/complete` — can we complete recovery and
   replace the account's keyset?

**Also probe:**
- `/api/v2/recovery-keys/policies` — what recovery policies are configured?
- `/api/v2/recover/continue` — alternate recovery path?
- `/api/v2/session-restore/restore-key` — can a saved session be restored
  without the original credentials?

**What we're looking for:** Any path that allows account recovery without
both the password and Secret Key. If the recovery flow can bypass 2SKD — even
partially — that breaks the security model.

---

#### Authenticated Attacks

**Prerequisite:** These steps require either:
- A valid test account on `bugbounty-ctf.1password.com` (if allowed by CTF rules)
- A session obtained via a pre-auth exploit (Steps 3.1–3.5)
- The 1Password Burp plugin (`burp-1password-session-analyzer`) configured with
  a known session key to encrypt/decrypt API traffic

**Setup for authenticated testing:**

The `X-AgileBits-MAC` header is an HMAC over the request, and
`X-AgileBits-Session-ID` identifies the session. All request/response bodies
are encrypted with the session key derived from the SRP handshake. To send
valid authenticated requests, we need to:

1. Complete an SRP handshake to obtain the session key
2. Use the session key to encrypt request bodies and compute MACs
3. Decrypt response bodies with the same key

This can be done via `srp_handshake` (if we have valid credentials) or by
building a custom tool that implements the session encryption layer:

```
create_custom_tool(
    name="1p_session_client",
    description="1Password authenticated API client with session encryption",
    code="..."
)
```

Alternatively, use the MITM proxy + WebCrypto hooks to capture a live session
and replay/modify requests through the Burp plugin.

#### Step 3.6 — Request Signing Analysis

Before attempting authenticated attacks, understand the MAC scheme:

```
browser_execute_js(code=`
    // Hook XMLHttpRequest/fetch to capture the MAC computation
    const origFetch = window.fetch;
    window.fetch = async function(...args) {
        const req = args[0] instanceof Request ? args[0] : new Request(...args);
        const headers = {};
        req.headers.forEach((v, k) => headers[k] = v);
        console.log('REQUEST:', req.url, headers);
        return origFetch.apply(this, args);
    };
`)
```

**Determine:**
- What is MAC'd? (URL, body, headers, timestamp?)
- What key is the MAC derived from? (Session key? A sub-key?)
- Is there a nonce/counter to prevent replay?
- Can requests be replayed if the MAC is valid?

If the MAC doesn't include a timestamp or counter, **replay attacks** may be
possible — capture a valid request and resend it with a different session.

#### Step 3.7 — Vault Encryption & Key Hierarchy

With a valid session, capture encrypted vault data and key material:

```
install_webcrypto_hooks(tab_name="1password-ctf")
# Navigate to vault, trigger item decryption
extract_key_hierarchy(tab_name="1password-ctf")
```

Then analyze:

```
analyze_key_hierarchy(session_data=<extracted_hierarchy>)
parse_vault_blob(encrypted_data="<captured_blob_hex>")
key_wrap_analysis(wrapped_keys=[...])
```

**Look for:**
- Nonce reuse across items (catastrophic for AES-GCM — enables key recovery)
- Key IDs that are sequential or predictable
- `exportKey` calls that expose raw AES keys (check `extractable` flag)
- Shared vault keys that multiple accounts can access
- Whether the AUK is used directly or a sub-key is derived

```
test_aead_integrity(encrypted_data="<blob_hex>",
                    target="https://bugbounty-ctf.1password.com",
                    endpoint_path="/api/v1/vault/items",
                    modifications="all", samples=3)
```

**Note:** AEAD modification requests must go through the session encryption
layer. Use the MITM proxy with WebCrypto hooks to intercept *after* the client
decrypts but *before* it processes, or modify the encrypted blobs at the
application layer.

#### Step 3.8 — Server-Side Logic Bugs (Authenticated)

With a valid encrypted session, test authorization boundaries. Every request
must be encrypted and MAC'd — use the session client tool from Step 3.6.

**Test systematically:**
- **IDOR**: Substitute vault UUIDs, item UUIDs, user UUIDs in encrypted
  request payloads. Can account A's session access account B's vaults?
- **Vault access boundaries**: `/api/v2/mycelium/v` — what is this endpoint?
  The name suggests a distributed/mesh data structure. Probe for cross-account
  data leakage.
- **Key rotation gaps**: After a password change, are old session keys
  invalidated? Can an old session key decrypt new vault data?
- **API version drift**: `/api/v1/vault/*` vs `/api/v2/vault` — do v1
  endpoints have weaker access controls?
- **Race conditions**: Concurrent requests to vault sharing endpoints —
  can a TOCTOU bug grant access to a vault during the sharing window?

#### Step 3.9 — Client-Side Attacks

The CSP is strict (`default-src 'none'`, no `unsafe-inline`/`unsafe-eval`,
SRI on all scripts, WASM hash whitelist). Traditional XSS is very difficult.
Focus on:

**JS bundle reverse engineering:**
```
# Download and analyze the main application bundle
browser_execute_js(code=`
    // Look for postMessage handlers — CSP doesn't restrict these
    const origAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, listener, opts) {
        if (type === 'message') console.log('postMessage handler registered:', listener.toString().substring(0, 200));
        return origAddEventListener.call(this, type, listener, opts);
    };
`)
```

**Attack vectors within CSP constraints:**
- `postMessage` handlers without origin validation — if the SPA accepts
  messages from `*.1password.com` frames, a compromised subdomain could inject
- `wasm-unsafe-eval` — the WASM hash whitelist mitigates this, but verify the
  hash check runs *before* WASM execution, not after
- Prototype pollution via `vendor-lodash` — lodash has had prototype pollution
  CVEs; check the version and whether `_.merge`/`_.set` are used with
  attacker-controlled input
- Service worker scope — if a service worker is registered, can its fetch
  handler be poisoned to intercept decrypted vault data?

**WASM hash whitelist bypass:**
The inline script patches `WebAssembly.compile/instantiate/validate` to verify
hashes. But:
- Does it patch `WebAssembly.compileStreaming` correctly? (Check: it converts
  to `ArrayBuffer` first, which is correct)
- Can the hash check be bypassed by loading WASM via a `Worker`? The CSP
  allows `worker-src 'self'` — a worker has its own scope and may not inherit
  the monkey-patched `WebAssembly` object
- Can the trusted hash list be modified before WASM loading? (Unlikely — the
  script runs inline before any external scripts load)

#### Step 3.10 — Independent Factor Attack (Conditional)

**Only if Step 3.4 found factor separation.**

If the server distinguishes wrong-password from wrong-key:

**Password attack (40-bit keyspace):**
```
offline_crack_setup(
    salt_hex="<captured_salt>",
    iterations=<captured_iterations>,
    algorithm="PBKDF2-HMAC-SHA256",
    verifier_hex="<captured_verifier>",
    wordlist="rockyou.txt"
)
```

Use the generated hashcat command in Kali:
```
kali_execute(command="hashcat -m 10900 -a 0 hash.txt rockyou.txt")
```

**Secret Key attack (128-bit keyspace):**
Infeasible by brute force. But if predictable components were found in
Step 2.3, the effective keyspace may be smaller.

**Combined attack with factor separation:**
If timing separation reveals which factor is wrong, an attacker can:
1. Fix a random Secret Key, brute-force the password (~2^40 attempts)
2. Fix the recovered password, brute-force the Secret Key (~2^128 attempts)
3. Step 2 is still infeasible, but step 1 alone may yield the password, which
   combined with other attacks (recovery flow, key hierarchy) may be sufficient


### Phase 4: Exploit Development & Reporting

#### Step 4.1 — Chain Findings

No single finding may be sufficient. Map the attack chain:

```
query_knowledge_graph(query="MATCH (t:target)-[:VULNERABLE_TO]->(v) RETURN t, v")
```

**Common chains that reach the flag:**
1. SRP zero-key -> valid session -> vault key via key hierarchy -> decrypt item
2. Factor separation -> password crack -> AUK recovery -> vault decrypt
3. XSS in authenticated context -> DOM exfiltration of decrypted note
4. IDOR on item endpoint -> encrypted blob -> key hierarchy attack -> decrypt
5. Public key substitution -> vault sharing -> attacker-encrypted keys -> decrypt

#### Step 4.2 — PoC Development

For any viable attack chain, build a complete PoC:

```
create_custom_tool(
    name="ctf_exploit",
    description="End-to-end exploit for 1Password CTF",
    code="async def ctf_exploit(target: str) -> dict: ..."
)
```

Or use the Kali container for compiled exploits:
```
kali_setup()
kali_execute(command="python3 /tmp/exploit.py --target bugbounty-ctf.1password.com")
```

The PoC must demonstrate: starting from zero, recover the plaintext "bad poetry"
secure note.

#### Step 4.3 — Report Generation

```
generate_report(
    title="1Password CTF — [Attack Class] Leading to Vault Content Recovery",
    findings=[...],
    evidence=[...],
    severity="critical"
)
save_report(format="markdown", path="1password_ctf_report.md")
```

**Report structure for HackerOne:**
1. Summary — one paragraph describing the vulnerability and impact
2. Attack chain — numbered steps from initial access to flag recovery
3. Evidence — screenshots, captured values, timing data, PoC output
4. Affected components — which layer(s) of the security model failed
5. Remediation — specific fix recommendations
6. Reproduction steps — exact commands and inputs to reproduce


## 4. Decision Tree

Quick reference for routing based on findings at each phase. Pre-auth attacks
run first because every authenticated attack requires a session.

```
START
  |
  v
[1.2] TLS downgrade possible? --YES--> File finding, test POODLE/BEAST
  |NO                                    (unlikely to reach vault data alone)
  v
[3.1] SRP zero-key accepted? --YES--> Session key known → skip to [3.7]
  |NO
  v
[3.2] SRP timing leak? --YES--> Quantify; byte-at-a-time if d > 0.8
  |NO                            (user enumeration, not direct key recovery)
  v
[3.3] KDF oracle leak? --YES--> Chain with [3.4] for offline cracking
  |NO
  v
[3.4] Factor separation? --YES--> [3.10] Independent password crack
  |NO                               (password-only: ~2^40 keyspace)
  v
[3.5] Recovery flow bypass? --YES--> Account takeover without 2SKD → [3.7]
  |NO                                  (highest-value pre-auth vector)
  v
  +----- No pre-auth break -----+
  |                              |
  | Need a valid session         |
  | (test account or Burp plugin)|
  v                              |
[3.6] Replay / MAC weakness? --YES--> Replay captured requests
  |NO                                   across sessions
  v
[3.7] AEAD misuse? --YES--> Nonce reuse = key recovery
  |NO                        Padding oracle = decrypt
  v
[3.8] IDOR / AuthZ bypass? --YES--> Access other account's
  |NO                                 encrypted blobs → [3.7]
  v
[3.9] Client-side attack? --YES--> DOM exfiltration of
  |NO                                decrypted note
  v
Re-evaluate:
  - API version differences (v1 vs v2 access controls)
  - Race conditions in vault sharing
  - Session-restore key brute force
  - CDN/cache poisoning of JS bundle
  - New CVEs in lodash, WASM runtime, dependencies
  - WASM Worker bypass of hash whitelist
```


## 5. Hardest Parts (White Paper Appendix A Acknowledgments)

The 1Password security white paper explicitly flags these as the weakest points.
They should receive the most attention:

| Appendix | Acknowledged Weakness | Our Tool Coverage |
|----------|----------------------|-------------------|
| A.1 | WebCrypto forces PBKDF2, cannot use Argon2 — weaker against GPU attacks | `benchmark_kdf_cracking`, `analyze_2skd_entropy`, `offline_crack_setup` |
| A.2 | JavaScript delivery is trusted — no code signing, TOFU model | `mitm_inject_response`, `browser_execute_js`, JS bundle analysis |
| A.3 | No user-to-user public key verification — server can substitute keys | `mitm_set_intercept_rule`, `key_wrap_analysis` |
| A.4 | Recovery groups expand the attack surface | `proxy_request` against recovery endpoints |
| A.5 | Server could withhold security updates or serve old client code | `mitm_inject_response` with older JS bundle |

The white paper's security model assumes a *non-malicious server*. Several
attacks (A.2, A.3, A.5) become viable if the server is compromised or if a
MITM is established. The CTF may intentionally weaken one of these assumptions.
