using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class OpenRedirectScanner : IScannerModule
    {
        public string Name => "OpenRedirectScanner";
        public string Description => "Detects Open Redirect vulnerabilities where user input controls redirect destinations.";

        private static readonly List<string> RedirectParameters = new()
        {
            "url", "redirect", "return", "returnUrl", "return_url", "ReturnUrl",
            "next", "goto", "target", "destination", "dest", "continue",
            "redirect_uri", "redirectUrl", "redir", "r", "page", "view"
        };

        private static readonly List<string> TestPayloads = new()
        {
            "https://evil.com",
            "http://attacker.com",
            "//evil.com",
            "https://evil.com/",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>"
        };

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var baseUrl = context.Target.Url;
                var uri = new Uri(baseUrl);

                // Test each redirect parameter
                foreach (var param in RedirectParameters.Take(8))
                {
                    foreach (var payload in TestPayloads.Take(4))
                    {
                        var testUrl = BuildTestUrl(baseUrl, param, payload);

                        try
                        {
                            var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, testUrl);
                            var response = await context.HttpClient.SendAsync(request);

                            // Check if redirect occurred
                            if (IsVulnerableRedirect(response, payload, uri.Host))
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Open Redirect",
                                    Description = "Application redirects to arbitrary URLs without validation. Attackers can use this to redirect users to phishing or malicious sites.",
                                    Severity = Severity.Medium,
                                    Evidence = $"Parameter: {param}\nPayload: {payload}\nResponse redirected to external domain",
                                    Remediation = "Validate and whitelist redirect destinations. Use relative URLs when possible. Warn users before external redirects.",
                                    Url = testUrl
                                });
                                break; // Found vulnerability for this parameter
                            }
                        }
                        catch
                        {
                            // Continue with next test
                        }
                    }
                }

                // Check for JavaScript-based redirects in page content
                var jsRedirectVulns = await CheckJavaScriptRedirects(context);
                vulnerabilities.AddRange(jsRedirectVulns);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Open Redirect Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private string BuildTestUrl(string baseUrl, string parameter, string payload)
        {
            var separator = baseUrl.Contains("?") ? "&" : "?";
            return $"{baseUrl}{separator}{parameter}={HttpUtility.UrlEncode(payload)}";
        }

        private bool IsVulnerableRedirect(System.Net.Http.HttpResponseMessage response, string payload, string originalHost)
        {
            // Check for redirect status codes
            var isRedirect = (int)response.StatusCode >= 300 && (int)response.StatusCode < 400;

            if (isRedirect && response.Headers.Location != null)
            {
                var location = response.Headers.Location.ToString();

                // Check if redirecting to our test payload domain
                if (location.Contains("evil.com", StringComparison.OrdinalIgnoreCase) ||
                    location.Contains("attacker.com", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Check for protocol-relative URLs to external domain
                if (payload.StartsWith("//") && location.Contains("//evil.com"))
                {
                    return true;
                }

                // Check if location is different from original host
                try
                {
                    var locationUri = new Uri(location, UriKind.RelativeOrAbsolute);
                    if (locationUri.IsAbsoluteUri && !locationUri.Host.Equals(originalHost, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                catch
                {
                    // Invalid URI
                }
            }

            return false;
        }

        private async Task<List<Vulnerability>> CheckJavaScriptRedirects(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var response = await context.HttpClient.GetAsync(context.Target.Url);
                var content = await response.Content.ReadAsStringAsync();

                // Look for JavaScript redirect patterns that use user-controlled input
                var dangerousPatterns = new[]
                {
                    @"window\.location\s*=\s*[^;]*\[",  // Array access
                    @"window\.location\s*=\s*[^;]*location\.",  // Using location properties
                    @"location\.href\s*=\s*[^;]*\[",
                    @"location\.replace\([^)]*location\.",
                    @"document\.location\s*=\s*[^;]*\["
                };

                foreach (var pattern in dangerousPatterns)
                {
                    if (Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Potential JavaScript-based Open Redirect",
                            Description = "Potentially unsafe JavaScript redirect pattern detected that may use user-controlled input.",
                            Severity = Severity.Low,
                            Evidence = $"Pattern found: {pattern}",
                            Remediation = "Validate and sanitize all redirect destinations. Use a whitelist of allowed redirect URLs.",
                            Url = context.Target.Url
                        });
                        break; // Report once per page
                    }
                }
            }
            catch
            {
                // Continue
            }

            return vulnerabilities;
        }
    }
}
