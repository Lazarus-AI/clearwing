# CBC Padding Oracle Exploitation

A padding oracle attack exploits an information leak where a system reveals whether the padding of a CBC-mode ciphertext is valid. By observing different error responses (or timing differences) for valid vs invalid padding, an attacker can decrypt any ciphertext byte-by-byte without knowing the encryption key. This attack applies to any system using CBC mode with PKCS#7 padding where the padding validity is distinguishable from decryption failure.

## Attack Theory

### PKCS#7 Padding Structure
CBC-mode block ciphers require input aligned to the block size (16 bytes for AES). PKCS#7 pads with N bytes of value N:
- 1 byte of padding: `0x01`
- 2 bytes: `0x02 0x02`
- 16 bytes (full block): `0x10` repeated 16 times

### The Oracle
After decrypting, the server checks padding validity. If it returns distinguishable responses:
- HTTP 200 (valid padding, valid data)
- HTTP 400 "invalid padding" (bad padding)
- HTTP 500 "processing error" (valid padding, bad data)

The attacker can distinguish case 2 from case 3, learning one bit of information per request.

### Vaudenay's Attack (Byte-at-a-Time Decryption)
For each byte position in the target block:
1. Modify the preceding ciphertext block's corresponding byte
2. Iterate through all 256 possible values
3. When the server accepts the padding, the intermediate state byte is revealed
4. XOR with the original ciphertext byte to recover the plaintext byte

Total requests: up to 256 * block_size * num_blocks (worst case ~4096 per block).

## Detection Methodology

### Step 1: Identify CBC Usage
```
install_webcrypto_hooks(tab_name)
get_webcrypto_log(tab_name, method_filter="encrypt")
get_webcrypto_log(tab_name, method_filter="decrypt")
```
Look for `algorithm.name == "AES-CBC"` in the crypto log. If the application uses AES-GCM exclusively, padding oracle attacks do not apply.

### Step 2: Test for Distinguishable Responses
```
timing_compare(
    target,
    path_a="/api/decrypt", body_a='{"data": "<valid_ciphertext>"}',
    path_b="/api/decrypt", body_b='{"data": "<corrupted_last_byte>"}',
    samples=50
)
```
Compare response times and status codes for valid vs corrupted ciphertext. A significant timing difference (p < 0.05) indicates a padding oracle.

### Step 3: Intercept and Modify Ciphertext
```
mitm_start(tab_name)
mitm_set_intercept_rule(url_pattern="*/api/decrypt*", log_body=True)
```
Capture encrypted payloads in transit for manipulation.

## Exploitation Steps

### Step 1: Baseline Valid Ciphertext
```
timing_probe(target, path="/api/decrypt", body='{"data": "<valid>"}', samples=30)
```
Establish baseline response time and status code for valid ciphertext.

### Step 2: Detect the Oracle
```
timing_compare(
    target,
    body_a='{"data": "<valid_ciphertext>"}', label_a="valid_padding",
    body_b='{"data": "<flipped_last_byte>"}', label_b="bad_padding",
    samples=50
)
```
If `significant=True` or response codes differ, a padding oracle exists.

### Step 3: Byte-at-a-Time Recovery
```
timing_bitwise_probe(
    target,
    body_template='{"data": "{{PROBE}}"}',
    charset="0123456789abcdef",
    known_prefix="<modified_iv_prefix>",
    samples_per_candidate=10,
    select="max"
)
```
For each byte position, probe all 256 values of the preceding block byte. The value producing valid padding (longest response or different status) reveals the intermediate state.

### Step 4: Reconstruct Plaintext
XOR recovered intermediate state with the original ciphertext block to obtain plaintext. Repeat for each block, working from the last block backward.

## Validation Criteria

- Different HTTP status codes for padding error vs data error
- Timing difference with p < 0.05 between valid and invalid padding
- Successful decryption of at least one byte via the oracle
- Application uses `AES-CBC` rather than an AEAD mode

## Known Mitigations

- Use AEAD modes exclusively (AES-GCM, ChaCha20-Poly1305) — these do not have padding
- If CBC is required, use Encrypt-then-MAC (verify MAC before decrypting)
- Return identical error responses for all decryption failures (constant-time)
- Do not expose decryption endpoints to unauthenticated users
- Implement rate limiting on decryption endpoints
