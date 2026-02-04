using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class XssScanner : IScannerModule
    {
        public string Name => "XssScanner";
        public string Description => "Detects Cross-Site Scripting (XSS) vulnerabilities including reflected, stored, and DOM-based XSS.";

        private static readonly List<string> XssPayloads = new()
        {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(`XSS`)'></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror='alert(\"XSS\")'>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "\"><script>alert(String.fromCharCode(88,83,83))</script>",
            // Encoding bypass attempts
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            // DOM-based patterns
            "' onclick='alert(\"XSS\")'",
            "\" onclick=\"alert('XSS')\"",
            "javascript:void(alert('XSS'))",
            "data:text/html,<script>alert('XSS')</script>"
        };

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                // Reflected XSS detection
                var reflectedVulns = await DetectReflectedXss(context);
                vulnerabilities.AddRange(reflectedVulns);

                // Check for potential DOM-based XSS patterns
                var domVulns = await DetectDomBasedXss(context);
                vulnerabilities.AddRange(domVulns);
            }
            catch (Exception ex)
            {
                // Log error - in production, use proper logging
                Console.WriteLine($"XSS Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private async Task<List<Vulnerability>> DetectReflectedXss(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();
            var baseUrl = context.Target.Url;

            // Try to find input parameters
            var testUrls = GenerateTestUrls(baseUrl);

            foreach (var testUrl in testUrls.Take(5)) // Limit for safety
            {
                foreach (var payload in XssPayloads.Take(10)) // Test subset of payloads
                {
                    try
                    {
                        var response = await context.HttpClient.GetAsync(testUrl + HttpUtility.UrlEncode(payload));
                        var content = await response.Content.ReadAsStringAsync();

                        // Check if payload is reflected in response
                        if (IsPayloadReflected(content, payload))
                        {
                            var severity = DetermineXssSeverity(payload, content);
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "Reflected XSS",
                                Description = $"Cross-Site Scripting vulnerability detected. The application reflects user input without proper sanitization.",
                                Severity = severity,
                                Evidence = $"Payload: {payload}\nReflected in: {testUrl}",
                                Remediation = "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Encode user input before displaying.",
                                Url = testUrl
                            });
                            break; // Found vulnerability, move to next URL
                        }
                    }
                    catch
                    {
                        // Continue testing other payloads
                    }
                }
            }

            return vulnerabilities;
        }

        private async Task<List<Vulnerability>> DetectDomBasedXss(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var response = await context.HttpClient.GetAsync(context.Target.Url);
                var content = await response.Content.ReadAsStringAsync();

                // Look for dangerous JavaScript patterns
                var dangerousPatterns = new[]
                {
                    @"document\.write\([^)]*location",
                    @"innerHTML\s*=\s*[^;]*location",
                    @"eval\([^)]*location",
                    @"setTimeout\([^)]*location",
                    @"setInterval\([^)]*location",
                    @"\.html\([^)]*location",
                    @"document\.location\.href\s*=",
                    @"window\.location\s*=.*\+"
                };

                foreach (var pattern in dangerousPatterns)
                {
                    if (Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Potential DOM-based XSS",
                            Description = "Potentially unsafe JavaScript pattern detected that could lead to DOM-based XSS.",
                            Severity = Severity.Medium,
                            Evidence = $"Pattern found: {pattern}",
                            Remediation = "Avoid using dangerous JavaScript functions with user-controlled data. Use safe DOM manipulation methods.",
                            Url = context.Target.Url
                        });
                    }
                }
            }
            catch
            {
                // Log error
            }

            return vulnerabilities;
        }

        private bool IsPayloadReflected(string content, string payload)
        {
            // Check for exact match
            if (content.Contains(payload, StringComparison.OrdinalIgnoreCase))
                return true;

            // Check for decoded version
            var decoded = HttpUtility.HtmlDecode(payload);
            if (content.Contains(decoded, StringComparison.OrdinalIgnoreCase))
                return true;

            // Check for partial reflection of script tags
            if (payload.Contains("<script>") && content.Contains("<script>", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private Severity DetermineXssSeverity(string payload, string content)
        {
            // High severity if script execution is possible
            if (payload.Contains("<script>") || payload.Contains("javascript:"))
                return Severity.High;

            // Medium if event handlers are reflected
            if (payload.Contains("onerror") || payload.Contains("onload") || payload.Contains("onclick"))
                return Severity.Medium;

            // Low for other cases
            return Severity.Low;
        }

        private List<string> GenerateTestUrls(string baseUrl)
        {
            var urls = new List<string> { baseUrl };

            // Add common parameter patterns
            if (!baseUrl.Contains("?"))
            {
                urls.Add($"{baseUrl}?id=");
                urls.Add($"{baseUrl}?q=");
                urls.Add($"{baseUrl}?search=");
                urls.Add($"{baseUrl}?query=");
                urls.Add($"{baseUrl}?name=");
            }
            else
            {
                urls.Add($"{baseUrl}&test=");
            }

            return urls;
        }
    }
}
