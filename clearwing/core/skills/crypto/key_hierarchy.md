# Key Wrapping and Derivation Hierarchy Attacks

Modern password managers use multi-layer key hierarchies: the user's password derives a master key, which unwraps a personal keyset, which unwraps per-vault keys, which encrypt individual items. Each layer adds defense-in-depth — but implementation flaws at any layer can expose the entire hierarchy. 1Password's hierarchy flows from password + Secret Key through PBKDF2 to an Account Unlock Key (AUK), then through key wrapping to vault keys and item keys.

## Attack Theory

### Key Hierarchy Structure (1Password Model)
```
Password + Secret Key
    |
    v (PBKDF2 + HKDF XOR)
Account Unlock Key (AUK)
    |
    v (AES-GCM unwrap)
Personal Keyset (RSA + symmetric keys)
    |
    v (RSA-OAEP or AES-KW unwrap)
Vault Keys (per-vault symmetric keys)
    |
    v (AES-GCM decrypt)
Item Keys / Item Data
```

### Extractable Key Material
WebCrypto `CryptoKey` objects can be marked `extractable: true` or `extractable: false`. Extractable keys can be exported via `exportKey()`, exposing raw key material to JavaScript. If intermediate keys in the hierarchy are extractable, an attacker with XSS or browser extension access can export them.

### Missing Wrapping Layer
If a layer is skipped (e.g., vault keys directly derived from AUK without an intermediate personal keyset), compromising the AUK gives immediate access to all vault data without the additional protection of key wrapping.

### Key Material in Client Storage
Keys stored in `localStorage`, `sessionStorage`, or IndexedDB persist beyond the session and can be extracted by XSS, malicious extensions, or physical access to the device.

### Key Reuse Across Contexts
If the same encryption key is used for multiple vaults or item types, a compromise of any item reveals the key for all items sharing that key.

## Detection Methodology

### Step 1: Reconstruct the Key Hierarchy
```
install_webcrypto_hooks(tab_name)
# ... perform login and access vault items ...
extract_key_hierarchy(tab_name)
```
Maps the complete derivation chain: `deriveBits` -> `importKey` -> `deriveKey` -> `wrapKey`/`unwrapKey` -> `encrypt`/`decrypt`. Captures intermediate key material if keys are extractable.

### Step 2: Inspect Key Wrapping Operations
```
get_webcrypto_log(tab_name, method_filter="wrapKey")
get_webcrypto_log(tab_name, method_filter="unwrapKey")
```
Identify which keys wrap which other keys. Check the wrapping algorithm (AES-KW, AES-GCM, RSA-OAEP) and whether wrapped key material is accessible.

### Step 3: Check Key Extractability
```
get_webcrypto_log(tab_name, method_filter="importKey")
get_webcrypto_log(tab_name, method_filter="generateKey")
```
Review `extractable` parameter in key import/generation calls. Keys marked `extractable: true` can be exported by any script in the same origin.

### Step 4: Capture Full Auth Flow
```
start_auth_recording("key_capture")
# ... login and access vault items ...
stop_auth_recording()
```
Unified timeline showing when each key is derived, imported, and used.

## Exploitation Steps

### Step 1: Map the Hierarchy
Run `extract_key_hierarchy(tab_name)` after login. The output shows:
- Derivation operations (PBKDF2, HKDF) with parameters
- Key import operations with extractable flags
- Wrapping/unwrapping operations with key relationships
- Encryption/decryption operations using leaf keys

### Step 2: Identify Extractable Keys
Search the webcrypto log for `extractable: true` entries. If any intermediate key (AUK, personal keyset key, vault key) is extractable, it can be exported:
```
get_webcrypto_log(tab_name, method_filter="exportKey")
```

### Step 3: Check Client-Side Storage
Use browser tools to inspect `localStorage`, `sessionStorage`, and IndexedDB for key material. Look for Base64-encoded or hex-encoded strings that match key lengths (128, 256, 512 bits).

### Step 4: Test Key Separation
Access items from multiple vaults and compare the keys used. If the same key encrypts items across vaults, key separation is broken.

### Step 5: Test Key Rotation
Change the account password and observe whether vault keys are re-wrapped. If vault keys remain unchanged after password change, the old password holder retains access.

## Weaknesses Checklist

| Weakness | Severity | Detection |
|----------|----------|-----------|
| Extractable intermediate keys | HIGH | `extractable: true` in importKey/generateKey |
| Key material in localStorage | HIGH | Browser storage inspection |
| Missing wrapping layer | MEDIUM | Hierarchy map shows direct derivation |
| Same key across vaults | MEDIUM | Key comparison across decrypt operations |
| No key rotation on password change | MEDIUM | Before/after password change comparison |
| Single-layer derivation | LOW | Only PBKDF2 -> encrypt, no wrapping |

## Validation Criteria

- Intermediate keys marked `extractable: true` in WebCrypto operations
- Raw key material found in browser localStorage/sessionStorage/IndexedDB
- Same encryption key used across multiple vaults or contexts
- Vault keys not re-wrapped after password change
- Missing wrapping layer between derived key and data encryption

## Known Mitigations

- Mark all `CryptoKey` objects as `extractable: false`
- Use separate wrapping keys per vault, wrapped by the personal keyset
- Never store raw key material in client-side storage
- Re-wrap vault keys on password change (key rotation)
- Include context (vault ID, item ID) in associated data for AEAD operations
- Zero key material from JavaScript heap after use (limited by GC, but `crypto.subtle` handles this internally for non-extractable keys)
