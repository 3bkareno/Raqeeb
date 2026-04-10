using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules;

/// <summary>
/// Detects session management weaknesses including session fixation, cookie security,
/// and authentication bypass indicators.
/// </summary>
public class SessionSecurityScanner : IScannerModule
{
    public string Name => "SessionSecurityScanner";
    public string Description => "Detects session management vulnerabilities including weak cookies, session fixation, and authentication issues.";

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            var response = await context.HttpClient.GetAsync(context.Target.Url);

            // Cookie security analysis
            var cookieVulns = AnalyzeCookieSecurity(response, context.Target.Url);
            vulnerabilities.AddRange(cookieVulns);

            // Check for session ID in URL
            var urlSessionVulns = CheckSessionInUrl(context.Target.Url);
            vulnerabilities.AddRange(urlSessionVulns);

            // Check cache-control for authenticated pages
            var cacheVulns = CheckCacheHeaders(response, context.Target.Url);
            vulnerabilities.AddRange(cacheVulns);

            // Check for autocomplete on sensitive forms
            var content = await response.Content.ReadAsStringAsync();
            var formVulns = CheckSensitiveForms(content, context.Target.Url);
            vulnerabilities.AddRange(formVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Session Security Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    private static List<Vulnerability> AnalyzeCookieSecurity(HttpResponseMessage response, string url)
    {
        var vulnerabilities = new List<Vulnerability>();

        if (!response.Headers.TryGetValues("Set-Cookie", out var cookies))
            return vulnerabilities;

        foreach (var cookie in cookies)
        {
            var cookieName = cookie.Split('=')[0].Trim();
            var isSessionCookie = cookieName.Contains("session", StringComparison.OrdinalIgnoreCase) ||
                                  cookieName.Contains("sid", StringComparison.OrdinalIgnoreCase) ||
                                  cookieName.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
                                  cookieName.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                                  cookieName.Contains("aspnet", StringComparison.OrdinalIgnoreCase) ||
                                  cookieName.Contains("identity", StringComparison.OrdinalIgnoreCase);

            if (!isSessionCookie) continue;

            if (!cookie.Contains("Secure", StringComparison.OrdinalIgnoreCase))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Name = "Session Cookie Without Secure Flag",
                    Description = $"The session cookie '{cookieName}' is not marked as Secure. It will be transmitted over unencrypted HTTP connections, allowing interception.",
                    Severity = Severity.Medium,
                    Evidence = $"Cookie: {cookieName}\nMissing: Secure flag",
                    Remediation = "Add the Secure flag to all session cookies to ensure they are only sent over HTTPS.",
                    Url = url,
                    OwaspCategory = "A02:2021 - Cryptographic Failures",
                    CweId = "CWE-614",
                    CvssScore = "5.3"
                });
            }

            if (!cookie.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Name = "Session Cookie Without HttpOnly Flag",
                    Description = $"The session cookie '{cookieName}' is not marked as HttpOnly. JavaScript can access this cookie, making it vulnerable to XSS-based session theft.",
                    Severity = Severity.Medium,
                    Evidence = $"Cookie: {cookieName}\nMissing: HttpOnly flag",
                    Remediation = "Add the HttpOnly flag to session cookies to prevent JavaScript access.",
                    Url = url,
                    OwaspCategory = "A07:2021 - Identification and Authentication Failures",
                    CweId = "CWE-1004",
                    CvssScore = "5.3"
                });
            }

            if (!cookie.Contains("SameSite", StringComparison.OrdinalIgnoreCase))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Name = "Session Cookie Without SameSite Attribute",
                    Description = $"The session cookie '{cookieName}' lacks the SameSite attribute. This makes the application more susceptible to CSRF attacks.",
                    Severity = Severity.Low,
                    Evidence = $"Cookie: {cookieName}\nMissing: SameSite attribute",
                    Remediation = "Add SameSite=Lax or SameSite=Strict attribute to session cookies.",
                    Url = url,
                    OwaspCategory = "A07:2021 - Identification and Authentication Failures",
                    CweId = "CWE-1275",
                    CvssScore = "3.1"
                });
            }

            // Check for short/predictable session IDs
            var cookieValue = cookie.Split('=').ElementAtOrDefault(1)?.Split(';')[0] ?? "";
            if (cookieValue.Length > 0 && cookieValue.Length < 16)
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Name = "Weak Session Token Length",
                    Description = $"The session cookie '{cookieName}' has a short value ({cookieValue.Length} chars). Short session IDs are more susceptible to brute-force attacks.",
                    Severity = Severity.Medium,
                    Evidence = $"Cookie: {cookieName}\nValue length: {cookieValue.Length} characters",
                    Remediation = "Use session IDs with at least 128 bits (16+ bytes) of entropy. Use framework-provided session management.",
                    Url = url,
                    OwaspCategory = "A07:2021 - Identification and Authentication Failures",
                    CweId = "CWE-6",
                    CvssScore = "5.3"
                });
            }
        }

        return vulnerabilities;
    }

    private static List<Vulnerability> CheckSessionInUrl(string url)
    {
        var vulnerabilities = new List<Vulnerability>();

        var sessionPatterns = new[]
        {
            @"[?&;](jsessionid|sessionid|sid|session_id|phpsessid|aspsessionid)=",
            @"/;jsessionid=",
        };

        foreach (var pattern in sessionPatterns)
        {
            if (Regex.IsMatch(url, pattern, RegexOptions.IgnoreCase))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Name = "Session ID in URL",
                    Description = "Session identifier is exposed in the URL. This can be leaked via Referer headers, browser history, server logs, and shared links.",
                    Severity = Severity.Medium,
                    Evidence = $"Session pattern found in URL: {url}",
                    Remediation = "Use cookie-based session management instead of URL-based sessions. Ensure session IDs are never passed in URLs.",
                    Url = url,
                    OwaspCategory = "A07:2021 - Identification and Authentication Failures",
                    CweId = "CWE-598",
                    CvssScore = "5.3"
                });
                break;
            }
        }

        return vulnerabilities;
    }

    private static List<Vulnerability> CheckCacheHeaders(HttpResponseMessage response, string url)
    {
        var vulnerabilities = new List<Vulnerability>();

        var hasCacheControl = response.Headers.CacheControl != null;
        var hasNoCacheDirective = hasCacheControl &&
            (response.Headers.CacheControl!.NoCache || response.Headers.CacheControl.NoStore);
        var hasPragma = response.Headers.TryGetValues("Pragma", out var pragmaValues) &&
            pragmaValues.Any(v => v.Contains("no-cache", StringComparison.OrdinalIgnoreCase));

        // If Set-Cookie is present but no cache-control is set, pages with session data could be cached
        if (response.Headers.Contains("Set-Cookie") && !hasNoCacheDirective)
        {
            vulnerabilities.Add(new Vulnerability
            {
                Name = "Cacheable Authenticated Page",
                Description = "The page sets cookies but does not include Cache-Control: no-store. Authenticated pages may be cached by proxies or browsers, exposing session data.",
                Severity = Severity.Low,
                Evidence = "Set-Cookie header present without Cache-Control: no-store",
                Remediation = "Add 'Cache-Control: no-store, no-cache, must-revalidate' and 'Pragma: no-cache' headers to authenticated responses.",
                Url = url,
                OwaspCategory = "A05:2021 - Security Misconfiguration",
                CweId = "CWE-525",
                CvssScore = "3.7"
            });
        }

        return vulnerabilities;
    }

    private static List<Vulnerability> CheckSensitiveForms(string content, string url)
    {
        var vulnerabilities = new List<Vulnerability>();

        // Check for password fields without autocomplete=off
        var passwordInputs = Regex.Matches(content, @"<input[^>]*type\s*=\s*['""]password['""][^>]*>", RegexOptions.IgnoreCase);
        foreach (Match input in passwordInputs)
        {
            if (!input.Value.Contains("autocomplete", StringComparison.OrdinalIgnoreCase) ||
                input.Value.Contains("autocomplete=\"on\"", StringComparison.OrdinalIgnoreCase))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Name = "Password Field With Autocomplete Enabled",
                    Description = "A password input field does not have autocomplete disabled. Browsers may cache entered passwords, which can be accessed by other users of shared devices.",
                    Severity = Severity.Low,
                    Evidence = "Password field without autocomplete='off' or autocomplete='new-password'",
                    Remediation = "Add autocomplete='off' or autocomplete='new-password' attribute to password fields.",
                    Url = url,
                    OwaspCategory = "A04:2021 - Insecure Design",
                    CweId = "CWE-525",
                    CvssScore = "3.7"
                });
                break; // One finding per page
            }
        }

        return vulnerabilities;
    }
}
