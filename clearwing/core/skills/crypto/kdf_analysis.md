# Key Derivation Function Analysis

Key Derivation Functions (KDFs) transform user passwords into cryptographic keys. The security of password-based systems depends critically on KDF parameters: algorithm choice, iteration count, salt quality, and output length. Weak KDF configuration enables offline brute-force attacks even when the protocol itself is sound. 1Password uses PBKDF2-HMAC-SHA256 via WebCrypto, as the Web Crypto API does not support memory-hard functions like Argon2.

## Attack Theory

### Insufficient Iterations
Low iteration counts allow faster offline brute-force. A modern GPU can compute billions of PBKDF2-SHA256 iterations per second. At 100,000 iterations, a common password dictionary can be exhausted in minutes.

### Salt Weaknesses
- Absent or empty salt enables precomputed rainbow table attacks
- Short salts (< 16 bytes) increase collision probability across users
- Predictable salts (username, email, sequential) enable targeted precomputation
- Salt reuse across users allows batch attacks

### Algorithm Selection
- PBKDF2: CPU-bound only, parallelizable on GPUs — weakest modern option
- bcrypt: Memory-limited to 4KB, moderate GPU resistance
- scrypt: Configurable memory-hardness, good GPU resistance
- Argon2id: Winner of the Password Hashing Competition, best GPU/ASIC resistance

### Output Length Mismatch
If the KDF output length exceeds the hash output length (e.g., 512-bit output from SHA-256), multiple hash rounds are computed independently, effectively halving the iteration cost.

## Detection Methodology

### Step 1: Extract Parameters from Auth Endpoint
```
srp_extract_verifier_info(target, username)
```
Returns the iteration count, algorithm, and salt from the SRP initialization response.

### Step 2: Capture Browser-Side KDF Operations
```
install_webcrypto_hooks(tab_name)
# ... trigger login flow ...
extract_srp_values(tab_name)
```
Captures `deriveBits` calls showing: algorithm name, hash function, iteration count, salt (hex), output length.

### Step 3: Record Full Derivation Chain
```
start_auth_recording("kdf_capture")
# ... trigger login flow ...
stop_auth_recording()
extract_key_hierarchy(tab_name)
```
Maps the complete chain: password -> PBKDF2 -> AUK -> key hierarchy.

## OWASP KDF Parameter Benchmarks (2023)

| Algorithm | Minimum Recommended | Notes |
|-----------|-------------------|-------|
| PBKDF2-HMAC-SHA256 | 600,000 iterations | OWASP 2023 guidance |
| PBKDF2-HMAC-SHA1 | 1,300,000 iterations | SHA-1 is faster, needs more rounds |
| bcrypt | Cost factor 10+ | ~100ms on modern hardware |
| scrypt | N=2^17, r=8, p=1 | ~100ms, 128MB memory |
| Argon2id | t=3, m=64MB, p=4 | Preferred for new implementations |

## Assessment Checklist

1. **Algorithm**: Is PBKDF2 used where Argon2id would be available? (WebCrypto forces PBKDF2 — note this as an inherent limitation, not a misconfiguration)
2. **Iterations**: Compare against OWASP minimums in the table above
3. **Salt**: Verify >= 16 bytes, random, unique per user
4. **Output length**: Should not exceed the underlying hash output length
5. **Hash function**: SHA-256 or SHA-512 (SHA-1 is deprecated for new systems)

## Validation Criteria

- Iteration count below OWASP minimum for the algorithm
- Salt shorter than 16 bytes or reused across users
- Salt derivable from public information (username, email)
- PBKDF2 output length exceeding 256 bits with SHA-256
- KDF algorithm is SHA-1 based PBKDF2

## Known Mitigations

- Use Argon2id where platform supports it (not available in WebCrypto)
- Set PBKDF2-HMAC-SHA256 iterations >= 600,000
- Generate 16+ byte cryptographically random salt per user
- Do not derive salt from user-controllable inputs
- Limit output length to the hash digest size
- Implement server-side pepper stored in HSM
- Plan for iteration count increases as hardware improves
