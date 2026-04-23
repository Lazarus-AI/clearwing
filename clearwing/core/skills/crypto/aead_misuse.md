# AEAD Misuse: AES-GCM Nonce Reuse and Tag Forgery

Authenticated Encryption with Associated Data (AEAD) provides both confidentiality and integrity in a single operation. AES-GCM is the most widely deployed AEAD mode, used in TLS 1.3, WebCrypto, and 1Password's vault encryption. However, AES-GCM has a critical fragility: reusing a nonce (IV) with the same key completely destroys both confidentiality and authenticity guarantees, enabling plaintext recovery and tag forgery.

## Attack Theory

### Nonce Reuse Catastrophe
AES-GCM encrypts by XORing plaintext with a keystream derived from (key, nonce). If two messages are encrypted with the same (key, nonce) pair:
```
C1 = P1 XOR Keystream
C2 = P2 XOR Keystream
C1 XOR C2 = P1 XOR P2
```
With known or guessable plaintext structure (e.g., JSON format), the attacker can recover both plaintexts.

### GHASH Key Recovery
The authentication tag in GCM is computed using a polynomial hash (GHASH) keyed by `H = AES_K(0)`. Two messages encrypted with the same nonce produce two tag equations with the same H. Solving the polynomial system recovers H, allowing the attacker to forge valid tags for arbitrary ciphertexts.

### Tag Truncation
AES-GCM produces a 128-bit tag. If the tag is truncated (e.g., to 32 or 64 bits), the probability of a random message passing authentication increases to `1/2^tag_bits`. With a 32-bit tag, forgery requires only ~2^32 attempts.

### Associated Data Omission
If authenticated data (AAD) is empty or does not include context (e.g., the vault ID, item ID, or user ID), encrypted data can be moved between contexts — a valid ciphertext from vault A decrypts successfully in vault B.

## Detection Methodology

### Step 1: Capture Encryption Operations
```
install_webcrypto_hooks(tab_name)
# ... trigger operations that encrypt/decrypt vault items ...
get_webcrypto_log(tab_name, method_filter="encrypt")
```
Collect all `encrypt` operations. Each entry includes algorithm parameters (name, iv, tagLength, additionalData).

### Step 2: Check for IV/Nonce Reuse
```
extract_srp_values(tab_name)
```
Review the encryption operations log. Look for duplicate IV values across different encrypt calls using the same key. Even two encryptions with the same IV constitutes a break.

### Step 3: Analyze Key-Nonce Pairing
```
extract_key_hierarchy(tab_name)
```
Map which keys are used with which nonces. Check:
- Are nonces generated randomly (96-bit random) or counter-based?
- Does the same key encrypt multiple items?
- Is the nonce derived from predictable data (item ID, timestamp)?

### Step 4: Inspect Tag Length
Review `tagLength` parameter in webcrypto log entries. Standard is 128 bits. Any value less than 128 is a weakness.

### Step 5: Check Associated Data
Review `additionalData` parameter. If null, empty, or missing context identifiers, cross-context attacks may be possible.

## Exploitation Steps

### Nonce Reuse Recovery
1. Identify two ciphertexts C1, C2 encrypted with the same (key, nonce) from webcrypto log
2. Compute `C1 XOR C2 = P1 XOR P2`
3. If P1 is known (e.g., a vault item with known structure), recover P2:
   `P2 = P1 XOR (C1 XOR C2)`
4. Recover GHASH key H from the two authentication tags
5. Forge valid tags for arbitrary modified ciphertexts

### Tag Truncation Exploitation
1. Observe `tagLength < 128` in webcrypto log
2. Compute forgery probability: `1 / 2^tagLength`
3. For tagLength=32: brute-force ~4 billion attempts to find a valid tag
4. For tagLength=64: 2^64 attempts (impractical without nonce reuse)

### Context Confusion
1. Capture encrypted item from vault A via webcrypto log
2. If AAD is empty, replay the ciphertext in a request targeting vault B
3. If the server decrypts successfully, context isolation is broken

## Validation Criteria

- Same IV/nonce observed for two or more encrypt operations with the same key
- Tag length less than 128 bits (`tagLength` parameter in webcrypto log)
- Empty or absent `additionalData` in encrypt operations
- Nonce generation from predictable sources (sequential counter without key rotation)

## Known Mitigations

- Never reuse a (key, nonce) pair — use random 96-bit nonces or a deterministic nonce scheme (SIV)
- Use full 128-bit authentication tags
- Include context identifiers in associated data (vault ID, item ID, user ID)
- Rotate encryption keys before the nonce space is exhausted (2^32 encryptions for random nonces)
- Consider AES-GCM-SIV for nonce-misuse resistance (tolerates reuse with reduced confidentiality but maintained authenticity)
- Monitor for nonce collisions in audit logs
