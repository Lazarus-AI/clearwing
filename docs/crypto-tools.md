# Cryptographic Protocol Tools

Tools for analyzing, testing, and attacking cryptographic protocols in the
network-pentest agent. Added to support the 1Password CTF engagement but
applicable to any target using SRP, PBKDF2, AES-GCM, or TLS.

All tools live under `clearwing/agent/tools/` and are registered via
`get_all_tools()` in `clearwing/agent/tools/__init__.py`. Each tool module
exports a `get_*_tools()` function that returns its tools. The registration
is lazy — importing one module does not pull in the others.

Tools that send network requests require human approval via `interrupt()`.
Pure-computation tools run without approval.

---

## TLS Inspection (`scan/tls_tools.py`)

Four tools for auditing TLS configuration, cipher suites, protocol downgrade
paths, and certificate strength.

### `scan_tls_config`

Probe a host's TLS configuration: negotiated protocol version, cipher suite,
certificate summary, and security headers.

```
scan_tls_config(host, port=443, timeout=10) -> dict
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | required | Target hostname or IP |
| `port` | `int` | `443` | TLS port |
| `timeout` | `int` | `10` | Connection timeout in seconds |

**Returns:** `protocol_version`, `cipher_suite`, `cipher_bits`,
`cipher_strength` rating, `certificate` (subject, issuer, SANs, key_bits,
signature_algorithm), `security_headers` (HSTS, HPKP, Expect-CT).

### `enumerate_cipher_suites`

Enumerate all cipher suites accepted by a TLS server using iterative exclusion.
Returns the server's full cipher preference list with security ratings.

```
enumerate_cipher_suites(host, port=443, protocol="TLSv1.2", timeout=10) -> dict
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | required | Target hostname |
| `port` | `int` | `443` | TLS port |
| `protocol` | `str` | `"TLSv1.2"` | Protocol version to enumerate |
| `timeout` | `int` | `10` | Per-connection timeout |

**Returns:** `cipher_suites` list (name, bits, protocol, strength,
preference_order), `total_accepted`, `strong_count`, `weak_count`, `assessment`.

### `test_tls_downgrade`

Test for TLS protocol downgrade vulnerabilities by attempting connections with
legacy protocols (SSLv3, TLS 1.0, TLS 1.1).

```
test_tls_downgrade(host, port=443, timeout=10) -> dict
```

**Returns:** Per-protocol accepted/rejected status, `known_vulnerabilities`
(POODLE, BEAST, etc.), `weak_cipher_issues`, `downgrade_possible` flag.

### `inspect_certificate`

Deep inspection of a server's TLS certificate: key strength, signature
algorithm, validity period, SANs, and trust assessment.

```
inspect_certificate(host, port=443, timeout=10) -> dict
```

**Returns:** Full certificate details, `key_strength` rating, `days_remaining`,
`issues` list, `trust_assessment`.

---

## SRP Protocol Testing (`crypto/srp_tools.py`)

Four tools for SRP-6a authentication testing. Backed by a full SRP-6a client
implementation in `clearwing/crypto/srp.py`.

### `srp_handshake`

Execute SRP-6a authentication handshake against a target, capturing all
intermediate cryptographic values.

```
srp_handshake(target, username, password="", secret_key="",
              group_bits=2048,
              auth_init_path="/api/v1/auth",
              auth_verify_path="/api/v1/auth/verify") -> dict
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | required | Base URL (e.g., `https://example.com`) |
| `username` | `str` | required | Account email/username |
| `password` | `str` | `""` | Account password |
| `secret_key` | `str` | `""` | 1Password Secret Key (A3-XXXXXX-...) |
| `group_bits` | `int` | `2048` | SRP group size |
| `auth_init_path` | `str` | `"/api/v1/auth"` | Auth init endpoint path |
| `auth_verify_path` | `str` | `"/api/v1/auth/verify"` | Auth verify endpoint path |

**Returns:** All SRP intermediate values (`salt_hex`, `A_hex`, `B_hex`, `u_hex`,
`S_hex`, `K_hex`, `M1_hex`, `M2_hex`), `server_params`, `init_response`,
`verify_response`, 2SKD details if `secret_key` provided, `success` flag.

**Requires:** `interrupt()` — sends network requests.

### `srp_fuzz_parameters`

Send malformed SRP parameters to test server-side validation: zero-key attacks,
oversized values, truncated proofs.

```
srp_fuzz_parameters(target, username, test_vectors="zero_key",
                    auth_init_path="/api/v1/auth",
                    auth_verify_path="/api/v1/auth/verify",
                    group_bits=2048) -> dict
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `test_vectors` | `str` | `"zero_key"` | Vector set: `"zero_key"`, `"multiples"`, `"malformed"`, `"all"` |

**Test vectors:**
- `zero_key`: A=0 (shared secret becomes zero regardless of password)
- `multiples`: A=N, A=2N, A=kN (modulus multiples)
- `malformed`: truncated proofs, oversized values
- `all`: all of the above

**Returns:** `vectors_tested` list, per-vector results (`A_value`,
`server_status`, `rejected` flag, `response_body`, `response_ms`),
`vulnerabilities` detected with severity.

### `srp_extract_verifier_info`

Extract SRP verifier parameters (salt, iterations, group) from the target's
auth endpoint. Optionally tests for username enumeration.

```
srp_extract_verifier_info(target, username, test_invalid=True,
                          auth_init_path="/api/v1/auth") -> dict
```

**Returns:** `valid_user` params (salt, iterations, algorithm, B_length, group),
`invalid_user` params (if `test_invalid=True`), `username_enumerable` flag,
`enumeration_signals` list.

### `srp_timing_attack`

Measure SRP authentication response timing across multiple samples to detect
information leakage.

```
srp_timing_attack(target, username, samples=20, test_type="username",
                  auth_init_path="/api/v1/auth",
                  auth_verify_path="/api/v1/auth/verify") -> dict
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `samples` | `int` | `20` | Samples per group |
| `test_type` | `str` | `"username"` | `"username"` (valid vs invalid), `"password"` (random_A vs zero_A), `"proof"` (random_M1 vs zero_M1) |

**Returns:** Per-group stats (mean, median, stdev, n), Welch t-test results
(`t_statistic`, `p_value`), Cohen's d effect size, `significant` flag.

---

## SRP Core Library (`crypto/srp.py`)

Pure-Python SRP-6a implementation used by the SRP tools. Key exports:

| Export | Description |
|--------|-------------|
| `SRPClient` | Full SRP-6a client: `generate_a()`, `compute_u()`, `compute_x()`, `compute_S()`, `compute_K()`, `compute_M1()`, `verify_M2()` |
| `SRP_GROUPS` | Standard groups (1024, 2048, 4096, 8192 bit) from RFC 5054 |
| `SRPGroupParams` | Dataclass: `N`, `g`, `bits` |
| `SRPHandshakeResult` | Dataclass: all intermediate values from a handshake |
| `derive_2skd(password, salt, iterations, secret_key_bytes)` | 1Password 2SKD: PBKDF2 then XOR with Secret Key, split into AUK + SRP-x |
| `parse_secret_key(key_string)` | Parse `A3-XXXXXX-...` format into raw bytes |

---

## Key Derivation Analysis (`crypto/kdf_tools.py`)

Four tools for KDF parameter assessment, cracking cost estimation, 2SKD
verification, and oracle detection.

### `analyze_kdf_parameters`

Assess KDF parameter security against OWASP 2023 benchmarks.

```
analyze_kdf_parameters(algorithm, iterations, salt_hex,
                       output_length=64, hash_function="sha256") -> dict
```

**Returns:** OWASP iteration ratio, salt compliance, `findings` list,
`risk_level` (LOW/MEDIUM/HIGH/CRITICAL), `recommendations`.

### `benchmark_kdf_cracking`

Estimate offline brute-force cost for a KDF configuration. Runs a local CPU
calibration and projects cracking time using published GPU benchmarks.

```
benchmark_kdf_cracking(algorithm="PBKDF2-HMAC-SHA256", iterations=650000,
                       password_entropy_bits=40.0,
                       calibration_rounds=100) -> dict
```

GPU profiles used for projection:

| Profile | Description | Approximate PBKDF2-SHA256 rate |
|---------|-------------|-------------------------------|
| `single_gpu_rtx4090` | Single RTX 4090 | ~1.8M iter/sec |
| `gpu_cluster_8x` | 8x RTX 4090 cluster | ~14.4M iter/sec |
| `cloud_100_gpu` | 100 cloud A100 GPUs | ~200M iter/sec |

**Returns:** Per-profile `keys_per_sec`, `time_to_exhaust` (human-readable),
`assessment` statement.

### `test_2skd_implementation`

Verify 1Password 2SKD implementation correctness by performing SRP handshakes
and checking key derivation properties.

```
test_2skd_implementation(target, username, password, secret_key="",
                         auth_init_path="/api/v1/auth",
                         auth_verify_path="/api/v1/auth/verify") -> dict
```

**Checks:**
- Secret Key XOR is applied after PBKDF2
- Derived key splits correctly into AUK (32 bytes) and SRP-x (32 bytes)
- Changing password produces a new AUK
- Iteration count meets OWASP minimum

**Requires:** `interrupt()` — sends network requests.

### `kdf_oracle_test`

Test if the server leaks KDF correctness information through timing differences
or response variations.

```
kdf_oracle_test(target, username, samples=30,
                auth_init_path="/api/v1/auth",
                auth_verify_path="/api/v1/auth/verify",
                warmup=5, outlier_method="iqr") -> dict
```

Sends interleaved SRP verify requests with two groups of derived keys and
compares server responses for timing and content differences.

**Returns:** Timing analysis (Welch's t-test, Cohen's d), `response_analysis`,
`oracle_detected` flag, `oracle_type` list.

---

## Credential Attack Tools (`crypto/credential_tools.py`)

Four tools for analyzing 1Password's Two-Secret Key Derivation (2SKD) system.
These validate the assumption that 2SKD makes brute force infeasible — they
don't attempt to break it directly.

### `analyze_2skd_entropy`

Calculate the effective keyspace of the combined (password x Secret Key) 2SKD
system. Pure computation — no network calls.

```
analyze_2skd_entropy(password_entropy_bits=40.0, secret_key_bits=128,
                     iterations=650000,
                     algorithm="PBKDF2-HMAC-SHA256") -> dict
```

**Returns:** `combined_entropy_bits` (password + secret key), per-GPU-profile
cracking time for password-only vs. 2SKD-protected, `cost_estimate_usd` at
cloud GPU rates ($2/hr per A100), `secret_key_is_dominant_factor` flag.

### `test_secret_key_validation`

Test whether the server distinguishes "wrong password" from "wrong Secret Key."
If the factors are separable, each can be attacked independently — collapsing
168 bits of combined entropy to max(40, 128).

```
test_secret_key_validation(target, username, password,
                           secret_key="", samples=20,
                           auth_init_path="/api/v1/auth",
                           auth_verify_path="/api/v1/auth/verify",
                           warmup=5, outlier_method="iqr") -> dict
```

**Separation signals tested:**
- **Timing:** Welch's t-test between wrong-key and wrong-password groups
- **Response body:** Different error messages or codes
- **HTTP status:** Different status codes for the two failure modes

**Returns:** `factor_separation` flag, `separation_signals` list (e.g.,
`["timing", "response_body"]`), per-group timing stats, `conclusion`.

**Requires:** `interrupt()` — sends network requests.

### `enumerate_secret_key_format`

Probe enrollment and authentication endpoints to determine Secret Key format,
entropy, and predictability.

```
enumerate_secret_key_format(target, username="",
                            enrollment_path="/api/v1/auth/enroll",
                            auth_init_path="/api/v1/auth") -> dict
```

**Analyzes the known format `A3-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX`:**
- Fixed prefix: `A3` (version/account type indicator)
- 7 segments of 6 characters
- 33-character alphabet: `0-9 A-H J-N P Q R S T V W X Y Z` (~5.04 bits/char)
- 26 random characters = ~131 bits of entropy

**Returns:** `format_analysis` (prefix, segment_count, charset, charset_size,
total_entropy_bits), `predictability_risks` list, `enrollment_probe` and
`auth_probe` results.

**Requires:** `interrupt()` — sends network requests.

### `offline_crack_setup`

Generate hashcat and john command lines for offline cracking of captured
PBKDF2/SRP parameters. Pure computation.

```
offline_crack_setup(salt_hex, iterations,
                    algorithm="PBKDF2-HMAC-SHA256",
                    verifier_hex="", secret_key_hex="",
                    wordlist="rockyou.txt",
                    password_entropy_bits=40.0) -> dict
```

**Hashcat modes:**

| Algorithm | Mode |
|-----------|------|
| PBKDF2-HMAC-SHA256 | 10900 |
| PBKDF2-HMAC-SHA1 | 12000 |
| PBKDF2-HMAC-SHA512 | 12100 |

**Returns:** `hashcat` (mode, command, hash_format, notes), `john` (format,
command), `cracking_estimates` per GPU profile, `2skd_active` flag, `feasibility`
statement. If `verifier_hex` provided, includes `hash_file_content` ready for
hashcat input.

When `secret_key_hex` is provided, notes that standard hashcat modes cannot
handle the 2SKD XOR step — a custom OpenCL kernel is required.

---

## Vault Encryption Analysis (`crypto/vault_tools.py`)

Four tools for analyzing 1Password's AES-256-GCM vault encryption and key
hierarchy.

### `parse_vault_blob`

Parse encrypted vault item structure to extract IV/nonce, ciphertext, auth tag,
key ID, and algorithm identifier. Supports JWE compact, JWE JSON, raw hex, and
raw base64 formats.

```
parse_vault_blob(encrypted_data, format_hint="auto") -> dict
```

**Returns:** Parsed structure (format, algorithm, IV, ciphertext, tag, key_id),
`findings` list (e.g., short IV, missing tag), `risk_level`.

### `analyze_key_hierarchy`

Analyze captured key hierarchy data from WebCrypto hooks. Maps the key
derivation chain: AUK -> personal keyset -> vault keys -> item keys.

```
analyze_key_hierarchy(session_data) -> dict
```

Takes the output from `extract_key_hierarchy()` (WebCrypto hooks).

**Returns:** `key_chain` list, `extractable_keys`, `wrapping_operations`,
`iv_reuse` list, `missing_layers` list, `findings`, `risk_level`.

### `test_aead_integrity`

Test AEAD implementation by sending modified ciphertexts to the server.

```
test_aead_integrity(encrypted_data, target, endpoint_path="/api/v1/vault/items",
                    modifications="all", request_template="",
                    samples=3) -> dict
```

**Modification types:** `bit_flip`, `tag_truncation`, `tag_substitution`,
`iv_zeroed`, `ciphertext_truncation`, `aad_removal`, `all`.

**Returns:** Per-modification results (accepted/rejected, response diff),
`vulnerabilities` list (e.g., "tag verification bypassed").

**Requires:** `interrupt()` — sends network requests.

### `key_wrap_analysis`

Analyze key wrapping scheme from captured wrapKey/unwrapKey operations.

```
key_wrap_analysis(wrapped_keys, unwrap_operations=None) -> dict
```

**Returns:** `wrapping_algorithms`, per-algorithm analysis, `key_distinguishability`,
AES-KW / RSA-OAEP specific checks, `findings`, `risk_level`.

---

## Timing Side-Channel Framework (`crypto/timing_tools.py`)

Three tools for systematic timing analysis. All use interleaved sampling,
configurable warmup, and outlier rejection for statistical rigor.

### `timing_probe`

Profile HTTP endpoint response timing with statistical analysis.

```
timing_probe(target, method="GET", path="/", headers=None, body="",
             samples=50, warmup=5, outlier_method="iqr",
             outlier_threshold=1.5) -> dict
```

**Returns:** Full statistics (mean, median, stdev, min, max, percentiles,
confidence interval, histogram), `raw_times_ms` list.

### `timing_compare`

Compare response timing of two HTTP request variants. Uses interleaved
sampling and Welch's t-test for statistical significance.

```
timing_compare(target,
               method_a="POST", path_a="/", headers_a=None, body_a="", label_a="group_a",
               method_b="POST", path_b="/", headers_b=None, body_b="", label_b="group_b",
               samples=50, warmup=5,
               outlier_method="iqr", outlier_threshold=1.5) -> dict
```

**Returns:** Per-group stats, `t_statistic`, `p_value`, Cohen's `d`,
`significant` flag, `mean_difference_ms`, `difference_ci_95`.

### `timing_bitwise_probe`

Byte-at-a-time timing attack. Tests each candidate character at a given
position, identifies the candidate producing the longest (or shortest) response.

```
timing_bitwise_probe(target, method="POST", path="/", headers=None,
                     body_template="", field_placeholder="{{PROBE}}",
                     known_prefix="", charset="0123456789abcdef",
                     position=0, samples_per_candidate=10,
                     warmup=3, outlier_method="iqr",
                     outlier_threshold=1.5, select="max") -> dict
```

**Returns:** Ranked `candidates` (char, mean_ms, median_ms, stdev_ms),
`best_candidate` with significance vs. second-best.

---

## MITM Proxy (`recon/mitm_proxy.py`)

Five tools for intercepting, logging, and modifying HTTP traffic through the
Playwright browser context.

### `mitm_start`

Enable MITM interception on a browser tab. All HTTP traffic through the tab
is logged to proxy history.

```
mitm_start(tab_name="default", url_pattern="**/*") -> dict
```

### `mitm_stop`

Disable MITM interception on a browser tab.

```
mitm_stop(tab_name="default") -> dict
```

### `mitm_set_intercept_rule`

Add a rule controlling which intercepted requests get their bodies logged.

```
mitm_set_intercept_rule(url_pattern, methods="",
                        log_request_body=True, log_response_body=True,
                        enabled=True) -> dict
```

### `mitm_get_decrypted_traffic`

Retrieve MITM-captured traffic from proxy history.

```
mitm_get_decrypted_traffic(url_contains="", method="", limit=50) -> dict
```

### `mitm_inject_response`

Set up a response injection rule. Matching requests receive the injected
response instead of the real server response.

```
mitm_inject_response(url_pattern, status=200, headers=None,
                     body="", remove=False) -> dict
```

**Requires:** `interrupt()` — modifies live traffic.

---

## WebCrypto Instrumentation (`recon/webcrypto_hooks.py`)

Five tools for instrumenting the browser's `crypto.subtle` API. Captures every
call to `encrypt`, `decrypt`, `sign`, `verify`, `digest`, `generateKey`,
`deriveKey`, `deriveBits`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`.

### `install_webcrypto_hooks`

Inject instrumentation into the page that wraps all SubtleCrypto methods with
logging.

```
install_webcrypto_hooks(tab_name="default") -> dict
```

### `get_webcrypto_log`

Retrieve captured crypto operations, optionally filtered by method name.

```
get_webcrypto_log(tab_name="default", method_filter="", limit=50) -> dict
```

### `clear_webcrypto_log`

Clear the captured crypto operation log.

```
clear_webcrypto_log(tab_name="default") -> dict
```

### `extract_srp_values`

Parse the crypto log to extract SRP handshake values and KDF parameters.

```
extract_srp_values(tab_name="default") -> dict
```

**Returns:** `kdf` list (algorithm, hash, iterations, salt), `derived_keys`,
`encryption_ops`, `timeline`.

### `extract_key_hierarchy`

Parse the crypto log to reconstruct the key derivation chain: password -> PBKDF2
-> AUK -> keyset decryption -> vault key unwrapping.

```
extract_key_hierarchy(tab_name="default") -> dict
```

**Returns:** `hierarchy` (linearized steps with operation, algorithm,
extractable flag), `captured_keys`, `encryption_operations`.

---

## Authentication Flow Recorder (`recon/auth_recorder.py`)

Three tools for capturing unified authentication flow timelines. Combines
proxy traffic, WebCrypto operations, and cookie state into a single record.

### `start_auth_recording`

Begin recording. Snapshots proxy and crypto state so that `stop_auth_recording`
captures only new events.

```
start_auth_recording(name, tab_name="default") -> dict
```

### `stop_auth_recording`

Stop recording, collect all new proxy/crypto events since start, return a
unified timeline.

```
stop_auth_recording() -> dict
```

**Returns:** `proxy_events` count, `crypto_events` count, `total_events`,
`cookies_at_start/stop`, `new_cookies`, `srp_values_found` flag, `timeline`
(ordered by timestamp, source + event_type per entry).

### `diff_auth_flows`

Compare two recorded auth flows to find differences in responses, timing,
crypto operations, and cookies.

```
diff_auth_flows(flow_a, flow_b) -> dict
```

**Returns:** `event_counts` (per flow and delta), `response_diffs`,
`timing_diffs` (per-step and total), `crypto_sequence_diffs`, `srp_diffs`,
`cookie_diffs`.

---

## Statistical Infrastructure (`crypto/stats.py`)

Shared statistical functions used by timing and credential tools:

| Function | Description |
|----------|-------------|
| `compute_stats(samples)` | Mean, median, stdev, min, max, percentiles, CI |
| `welch_t_test(group_a, group_b)` | Welch's t-test (unequal variance) |
| `cohens_d(group_a, group_b)` | Cohen's d effect size |
| `apply_outlier_rejection(samples, method, threshold)` | IQR or z-score outlier removal |

---

## Knowledge Graph Integration

All crypto tools automatically populate the knowledge graph via populator
blocks in `clearwing/agent/runtime.py`. Entity types and relationships:

**Entity types:** `protocol`, `algorithm`, `key_material`, `certificate`,
`kdf_config`

**Relationships:** `USES_ALGORITHM`, `DERIVES_KEY`, `WRAPS_KEY`, `DECRYPTS`,
`AUTHENTICATES_WITH`, `PRESENTS_CERT`, `VULNERABLE_TO`

**Tool-specific populators:**
- `scan_tls_config` -> `certificate` + `algorithm` entities
- `srp_handshake` -> `protocol` entity with SRP parameters
- `analyze_kdf_parameters` -> `kdf_config` entity with compliance assessment
- `analyze_2skd_entropy` -> `kdf_config` with `combined_entropy_bits`
- `test_secret_key_validation` -> `exploit` entity if factor separation found
- `enumerate_secret_key_format` -> `key_material` entity with entropy
- `offline_crack_setup` -> `cracking_feasibility` on KDF config
- `parse_vault_blob` -> `algorithm` entity
- `key_wrap_analysis` -> `algorithm` + `key_material` entities

---

## Findings Schema

Crypto findings use extended fields in `clearwing/findings/types.py`:

| Field | Type | Example |
|-------|------|---------|
| `crypto_protocol` | `str` | `"SRP-6a"`, `"TLS 1.3"` |
| `algorithm` | `str` | `"PBKDF2-HMAC-SHA256"`, `"AES-256-GCM"` |
| `crypto_attack_class` | `str` | `"timing_side_channel"`, `"parameter_validation"`, `"nonce_reuse"` |
| `key_material_exposed` | `str` | Description of what key material is at risk |
| `crypto_evidence` | `dict` | Timing measurements, parameter dumps, etc. |

**Crypto-specific evidence levels:**
- `parameter_anomaly` — KDF iterations too low, weak SRP group
- `timing_confirmed` — Statistically significant timing leak
- `assumption_broken` — Crypto assumption violated (e.g., S=0)
- `key_material_recovered` — Actual key material obtained

---

## Crypto Skill Pack

Attack methodology playbooks in `clearwing/core/skills/crypto/`. Loaded via
`load_skills(skill_name="<name>")`.

| Skill | File | Coverage |
|-------|------|----------|
| SRP Attacks | `srp_attacks.md` | Zero-key, parameter manipulation, verifier theft, session key recovery, 2SKD factor separation |
| KDF Analysis | `kdf_analysis.md` | OWASP compliance, iteration count assessment, 2SKD verification, cracking cost estimation |
| Timing Attacks | `timing_attacks.md` | Network timing methodology, drift cancellation, statistical rigor, byte-at-a-time recovery |
| AEAD Misuse | `aead_misuse.md` | AES-GCM nonce reuse, GHASH key recovery, tag truncation, associated data omission |
| Key Hierarchy | `key_hierarchy.md` | Key wrapping attacks, derivation chain analysis, padding oracles, key rotation testing |
| Padding Oracle | `padding_oracle.md` | CBC mode padding oracle, Vaudenay byte-at-a-time decryption methodology |
| TLS Assessment | `tls_assessment.md` | Protocol downgrade (POODLE, BEAST), weak ciphers, certificate validation |

| CVE Research | `cve_research.md` | Local CVE database search, product/protocol/CWE queries, cross-referencing with knowledge graph |

Each skill provides: attack theory, detection methodology, exploitation steps
(with specific tool invocations), validation criteria, and known mitigations.


---

## CVE Database (`data/cve_tools.py`)

Three tools for maintaining and querying a local mirror of the NVD CVE List V5
(346k+ CVEs). Uses SQLite with FTS5 for fast full-text search.

### `cve_db_update`

Download and index the CVE database.

```python
cve_db_update(
    zip_path: str = "",  # path to local cvelistV5-main.zip; if empty, downloads from GitHub (~550 MB)
) -> dict  # {"status": "success", "records": int, "db_path": str}
```

The database is stored at `~/.clearwing/cve/cve.db`. If `zip_path` is provided,
uses the local file instead of downloading. Extracts all CVE JSON records,
parses metadata (CVSS, CWE, affected products, descriptions), and builds an
FTS5 index for full-text search.

**No `interrupt()` when using local zip.** Downloads require approval.

### `cve_search`

Full-text search across the CVE database.

```python
cve_search(
    query: str,              # FTS5 query: "SRP bypass", "1password OR agilebits"
    min_cvss: float = 0.0,   # minimum CVSS score filter
    max_results: int = 25,   # cap on returned results
    date_after: str = "",    # only CVEs published after this date (YYYY-MM-DD)
    cwe: str = "",           # filter by CWE ID (e.g. "CWE-287")
) -> dict  # {"count": int, "total_matches": int, "results": [...]}
```

Results are sorted by CVSS score descending. Supports FTS5 syntax: `AND`, `OR`,
`NOT`, `"exact phrase"`, `prefix*`.

### `cve_lookup`

Look up a specific CVE by ID.

```python
cve_lookup(
    cve_id: str,  # e.g. "CVE-2022-32550"
) -> dict  # full record: description, CVSS, CWE, affected products, dates
```

Returns the complete CVE record including parsed affected product list.
