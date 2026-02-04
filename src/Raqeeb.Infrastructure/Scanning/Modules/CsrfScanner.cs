using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class CsrfScanner : IScannerModule
    {
        public string Name => "CsrfScanner";
        public string Description => "Detects Cross-Site Request Forgery (CSRF) vulnerabilities by checking for CSRF tokens and protective headers.";

        private static readonly List<string> CsrfTokenNames = new()
        {
            "csrf_token",
            "csrftoken",
            "csrf-token",
            "_csrf",
            "csrf",
            "token",
            "_token",
            "authenticity_token",
            "__requestverificationtoken",
            "anti-csrf-token"
        };

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var response = await context.HttpClient.GetAsync(context.Target.Url);
                var content = await response.Content.ReadAsStringAsync();
                var headers = response.Headers;

                // Check for forms without CSRF protection
                var formsVulnerabilities = CheckFormsForCsrfTokens(content, context.Target.Url);
                vulnerabilities.AddRange(formsVulnerabilities);

                // Check SameSite cookie attribute
                var sameSiteVulnerabilities = CheckSameSiteCookies(response, context.Target.Url);
                vulnerabilities.AddRange(sameSiteVulnerabilities);

                // Check for protective headers
                var headerVulnerabilities = CheckProtectiveHeaders(response, context.Target.Url);
                vulnerabilities.AddRange(headerVulnerabilities);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"CSRF Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private List<Vulnerability> CheckFormsForCsrfTokens(string content, string url)
        {
            var vulnerabilities = new List<Vulnerability>();

            // Find all forms
            var formPattern = @"<form[^>]*>(.*?)</form>";
            var formMatches = Regex.Matches(content, formPattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);

            foreach (Match formMatch in formMatches)
            {
                var formContent = formMatch.Value;

                // Check if form uses POST method (CSRF is mainly a concern for state-changing operations)
                var isPostForm = Regex.IsMatch(formContent, @"method\s*=\s*['""]post['""]", RegexOptions.IgnoreCase);

                if (isPostForm)
                {
                    // Check for CSRF token
                    var hasCsrfToken = CsrfTokenNames.Any(tokenName =>
                        Regex.IsMatch(formContent, $@"name\s*=\s*[""{tokenName}""]", RegexOptions.IgnoreCase));

                    if (!hasCsrfToken)
                    {
                        // Extract form action if available
                        var actionMatch = Regex.Match(formContent, @"action\s*=\s*['""]([^'""]*)['""]", RegexOptions.IgnoreCase);
                        var action = actionMatch.Success ? actionMatch.Groups[1].Value : "unknown";

                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Missing CSRF Token",
                            Description = "Form without CSRF protection detected. This form can be submitted from external sites, potentially leading to CSRF attacks.",
                            Severity = Severity.Medium,
                            Evidence = $"Form action: {action}\nForm method: POST\nNo CSRF token found in form",
                            Remediation = "Implement CSRF tokens for all state-changing operations. Use frameworks' built-in CSRF protection (e.g., ASP.NET Core's AntiForgeryToken).",
                            Url = url
                        });
                    }
                }
            }

            return vulnerabilities;
        }

        private List<Vulnerability> CheckSameSiteCookies(System.Net.Http.HttpResponseMessage response, string url)
        {
            var vulnerabilities = new List<Vulnerability>();

            // Check Set-Cookie headers
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    // Check if cookie is a session cookie (contains common session identifiers)
                    var isSessionCookie = cookie.ToLower().Contains("session") ||
                                         cookie.ToLower().Contains("sid") ||
                                         cookie.ToLower().Contains("auth") ||
                                         cookie.ToLower().Contains("token");

                    if (isSessionCookie)
                    {
                        // Check for SameSite attribute
                        if (!cookie.Contains("SameSite=", StringComparison.OrdinalIgnoreCase))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "Missing SameSite Cookie Attribute",
                                Description = "Session cookie without SameSite attribute detected. This increases CSRF vulnerability risk.",
                                Severity = Severity.Medium,
                                Evidence = $"Cookie: {cookie.Split(';')[0]}...\nMissing SameSite attribute",
                                Remediation = "Add SameSite=Strict or SameSite=Lax attribute to session cookies. SameSite=Strict provides strongest protection.",
                                Url = url
                            });
                        }
                        else if (cookie.Contains("SameSite=None", StringComparison.OrdinalIgnoreCase))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "Weak SameSite Cookie Attribute",
                                Description = "Session cookie uses SameSite=None, which offers no CSRF protection.",
                                Severity = Severity.Low,
                                Evidence = $"Cookie: {cookie.Split(';')[0]}...\nSameSite=None detected",
                                Remediation = "Change to SameSite=Strict or SameSite=Lax for better CSRF protection.",
                                Url = url
                            });
                        }
                    }
                }
            }

            return vulnerabilities;
        }

        private List<Vulnerability> CheckProtectiveHeaders(System.Net.Http.HttpResponseMessage response, string url)
        {
            var vulnerabilities = new List<Vulnerability>();

            // Check for Origin/Referer validation hints
            // Note: We can't fully test server-side validation, but we can check for related headers
            
            // Check if server sends CORS headers (which might indicate API endpoints vulnerable to CSRF)
            if (response.Headers.Contains("Access-Control-Allow-Origin"))
            {
                var origins = response.Headers.GetValues("Access-Control-Allow-Origin").ToList();
                if (origins.Contains("*"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Overly Permissive CORS Policy",
                        Description = "Access-Control-Allow-Origin is set to '*', which may allow CSRF attacks from any origin.",
                        Severity = Severity.Medium,
                        Evidence = "Access-Control-Allow-Origin: *",
                        Remediation = "Restrict CORS to specific trusted origins. Implement proper CSRF protection for API endpoints.",
                        Url = url
                    });
                }
            }

            return vulnerabilities;
        }
    }
}
