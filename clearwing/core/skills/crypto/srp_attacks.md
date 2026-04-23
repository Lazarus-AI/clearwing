# SRP-6a Protocol Attacks

SRP-6a (Secure Remote Password) provides zero-knowledge password proof without transmitting the password or its hash. However, implementation flaws — particularly missing parameter validation — can allow authentication bypass, session key prediction, and username enumeration. 1Password uses SRP-6a with Two-Secret Key Derivation (2SKD), combining the user password with a Secret Key before deriving the SRP verifier.

## Attack Theory

### Zero-Key Attack
If the server does not validate that `A % N != 0`, the client can send `A = 0` (or any multiple of N: A=N, A=2N, A=3N). This forces the shared secret `S = 0` regardless of the password, making the session key `K = H(0)` a known constant. The attacker can then compute valid proof `M1` without knowing the password.

### Username Enumeration
Servers may leak valid usernames through:
- Different response structures for valid vs invalid users (e.g., returning salt+B only for valid users)
- Timing differences in database lookups or SRP computation
- Distinct error messages or HTTP status codes

### Verifier Theft
If an attacker obtains the SRP verifier `v = g^x mod N` from the server database, they can mount an offline dictionary attack against the password. The verifier is equivalent to a salted password hash.

### M1 Proof Forgery
With a predictable session key (e.g., from a zero-key attack), the attacker can compute `M1 = H(H(N) XOR H(g) | H(I) | salt | A | B | K)` and authenticate as any user.

## Detection Methodology

1. Check if the auth init endpoint returns different response structures for valid vs invalid usernames
2. Measure timing differences between valid and invalid username requests
3. Test whether the server accepts degenerate A values (0, N, multiples of N)
4. Inspect the SRP group parameters (prime size, generator) for known-weak groups

## Exploitation Steps

### Step 1: Extract SRP Parameters
```
srp_extract_verifier_info(target, username, test_invalid=True)
```
Extracts salt, iterations, B, algorithm, and group parameters. With `test_invalid=True`, compares responses for valid vs invalid usernames to detect enumeration.

### Step 2: Capture Client-Side SRP Computation
```
install_webcrypto_hooks(tab_name)
# ... trigger login flow in browser ...
extract_srp_values(tab_name)
```
Captures PBKDF2 derivation parameters, the 2SKD XOR step, and all intermediate SRP values from the browser.

### Step 3: Execute Legitimate Handshake
```
srp_handshake(target, username, password, secret_key)
```
Performs a complete SRP-6a handshake to capture all intermediate values (A, B, salt, u, S, K, M1, M2) as a baseline.

### Step 4: Fuzz SRP Parameters
```
srp_fuzz_parameters(target, username, test_vectors="all")
```
Sends malformed A values: A=0, A=N, A=2N, A=3N, A=1, A=N-1, oversized values, empty, and non-numeric. Records which are accepted vs rejected.

### Step 5: Timing Analysis
```
srp_timing_attack(target, username, samples=20, test_type="username")
srp_timing_attack(target, username, samples=20, test_type="proof")
```
Statistical comparison of response times for valid vs invalid usernames, and valid vs invalid proof values.

### Step 6: Full Auth Flow Comparison
```
start_auth_recording("valid_login")
# ... login with correct credentials ...
stop_auth_recording()

start_auth_recording("invalid_login")
# ... login with wrong password ...
stop_auth_recording()

diff_auth_flows("valid_login", "invalid_login")
```
Unified comparison showing response body differences, timing deltas, crypto operation divergence, and cookie state transitions.

## 2SKD-Specific Attacks

1Password's Two-Secret Key Derivation combines password and Secret Key:
```
AUK = PBKDF2(password, salt, iterations) XOR HKDF(secret_key)
x = H(AUK)
v = g^x mod N
```

Attack vectors:
- If Secret Key is not incorporated (XOR step skipped), password-only offline attack is feasible
- If PBKDF2 iterations are low, combined brute-force of password space is tractable
- If the XOR is applied incorrectly, factors may be attackable independently

## Validation Criteria

- **CRITICAL**: Server accepts A=0 or A=N — zero-key vulnerability confirmed
- Timing differential with p < 0.05 for username enumeration
- Different response structure for valid vs invalid users
- Session key K = H(0) produces valid M1 — authentication bypass confirmed
- PBKDF2 iterations below OWASP minimum (600,000 for SHA-256)

## Known Mitigations

- Validate `A % N != 0` before computing shared secret
- Use constant-time comparison for M1 verification (`hmac.compare_digest`)
- Return uniform response structure for valid and invalid usernames
- Use a safe prime group of at least 2048 bits
- Enforce minimum PBKDF2 iterations per current OWASP guidelines
- Store verifiers with strong access controls (equivalent to password hashes)
