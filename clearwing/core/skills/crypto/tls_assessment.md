# TLS Configuration Assessment

Transport Layer Security (TLS) protects data in transit between client and server. A thorough TLS assessment validates protocol versions, cipher suite selection, certificate strength, and security headers. Misconfigurations — such as supporting legacy protocols or weak ciphers — enable protocol downgrade attacks, traffic decryption, and man-in-the-middle interception. 1Password claims TLS 1.2+ with strong cipher suites; this playbook verifies those claims.

## Attack Theory

### Protocol Downgrade
An active attacker can manipulate the TLS handshake to force a weaker protocol version:
- **SSLv3**: Vulnerable to POODLE (CVE-2014-3566) — CBC padding oracle in the protocol itself
- **TLS 1.0**: Vulnerable to BEAST (CVE-2011-3389) — chosen-plaintext attack on CBC
- **TLS 1.1**: Deprecated per RFC 8996 — no critical vulnerability, but lacks modern features

### Weak Cipher Suites
- **EXPORT ciphers**: 40-56 bit keys, trivially breakable — enables FREAK (CVE-2015-0204)
- **DHE with small groups**: DH parameters < 1024 bits — enables Logjam (CVE-2015-4000)
- **3DES/DES-CBC3**: 64-bit block size — enables SWEET32 (CVE-2016-2183) birthday attack
- **RC4**: Biases in keystream — statistical plaintext recovery
- **NULL/anon ciphers**: No encryption or authentication

### Certificate Issues
- RSA key < 2048 bits: factorable with moderate resources
- SHA-1 signature: collision attacks demonstrated (SHAttered)
- Expired certificate: browsers warn but may still connect
- Self-signed: no third-party trust validation
- Hostname mismatch: potential MITM indicator

## Detection Methodology

### Step 1: Quick Configuration Snapshot
```
scan_tls_config(host, port=443)
```
Returns: negotiated protocol, cipher suite, cipher strength rating, certificate summary (subject, issuer, key size, signature algorithm, validity), and security headers (HSTS, HPKP, Expect-CT).

### Step 2: Full Cipher Enumeration
```
enumerate_cipher_suites(host, port=443, protocol="TLSv1.2")
enumerate_cipher_suites(host, port=443, protocol="TLSv1.3")
```
Iterative exclusion reveals the server's complete cipher preference list with security ratings per cipher.

### Step 3: Downgrade Testing
```
test_tls_downgrade(host, port=443)
```
Attempts connections with SSLv3, TLS 1.0, and TLS 1.1. Reports which are accepted and flags associated vulnerabilities (POODLE, BEAST, etc.).

### Step 4: Certificate Deep Inspection
```
inspect_certificate(host, port=443)
```
Detailed certificate analysis: key strength rating, signature algorithm, days remaining, SANs, self-signed detection, hostname match.

## Cipher Suite Severity Ratings

| Cipher Property | Severity | Examples |
|----------------|----------|----------|
| NULL encryption | CRITICAL | NULL-SHA, NULL-MD5 |
| EXPORT grade | CRITICAL | EXP-RC4-MD5, EXP-DES-CBC-SHA |
| Anonymous key exchange | CRITICAL | ADH-*, AECDH-* |
| RC4 stream cipher | HIGH | RC4-SHA, RC4-MD5 |
| DES (56-bit) | HIGH | DES-CBC-SHA |
| 3DES (64-bit block) | MEDIUM | DES-CBC3-SHA |
| CBC + SHA-1 (no AEAD) | LOW | AES128-CBC-SHA |
| GCM / ChaCha20 | NONE | AES128-GCM-SHA256, CHACHA20-POLY1305 |

## Certificate Checklist

- [ ] RSA key >= 2048 bits or ECDSA P-256+
- [ ] SHA-256 or stronger signature algorithm
- [ ] Certificate not expired (check days remaining)
- [ ] Certificate not self-signed
- [ ] Subject/SAN matches the target hostname
- [ ] HSTS header present with `max-age >= 31536000`
- [ ] HSTS includes `includeSubDomains`

## Exploitation Steps

### Step 1: Identify Weaknesses
Run all four detection tools. Cross-reference results:
- If `test_tls_downgrade` shows legacy protocols accepted AND `enumerate_cipher_suites` shows weak ciphers, downgrade + cipher exploitation is viable
- If `inspect_certificate` shows key < 2048 bits, certificate factoring may be feasible

### Step 2: MITM via Downgrade
If SSLv3 or TLS 1.0 is accepted:
```
mitm_start(tab_name)
```
With control of the network path, force the client to downgrade by blocking TLS 1.2+ ServerHello responses.

### Step 3: Verify HSTS Enforcement
Check `security_headers` from `scan_tls_config` results. Missing HSTS allows SSL stripping attacks on the first connection.

## Validation Criteria

- Server accepts SSLv3, TLS 1.0, or TLS 1.1 connections
- Any cipher rated "weak" or "insecure" in the enumeration results
- Certificate key < 2048 bits RSA or < 256 bits ECDSA
- SHA-1 signature algorithm on the certificate
- Missing or weak HSTS header (max-age < 31536000)
- Certificate expired or hostname mismatch

## Known Mitigations

- Disable SSLv3, TLS 1.0, and TLS 1.1 — support TLS 1.2+ only
- Configure AEAD cipher suites only (AES-GCM, ChaCha20-Poly1305)
- Use RSA >= 2048 or ECDSA P-256+ certificates with SHA-256+ signatures
- Enable HSTS with `max-age=31536000; includeSubDomains; preload`
- Implement Certificate Transparency (Expect-CT header)
- Prefer server cipher order to enforce strong suite selection
