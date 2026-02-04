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
    public class ClickjackingScanner : IScannerModule
    {
        public string Name => "ClickjackingScanner";
        public string Description => "Detects Clickjacking vulnerabilities by checking for X-Frame-Options and Content-Security-Policy frame-ancestors headers.";

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var response = await context.HttpClient.GetAsync(context.Target.Url);

                // Check X-Frame-Options header
                var xFrameVulns = CheckXFrameOptions(response, context.Target.Url);
                vulnerabilities.AddRange(xFrameVulns);

                // Check Content-Security-Policy frame-ancestors
                var cspVulns = CheckCspFrameAncestors(response, context.Target.Url);
                vulnerabilities.AddRange(cspVulns);

                // Check for frame-busting code
                var frameBustingVulns = await CheckFrameBustingCode(context);
                vulnerabilities.AddRange(frameBustingVulns);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Clickjacking Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private List<Vulnerability> CheckXFrameOptions(System.Net.Http.HttpResponseMessage response, string url)
        {
            var vulnerabilities = new List<Vulnerability>();

            if (!response.Headers.Contains("X-Frame-Options"))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Name = "Missing X-Frame-Options",
                    Description = "The X-Frame-Options header is not set. The application may be vulnerable to clickjacking attacks.",
                    Severity = Severity.Medium,
                    Evidence = "X-Frame-Options header not found",
                    Remediation = "Add X-Frame-Options header with value 'DENY' or 'SAMEORIGIN' to prevent framing by malicious sites.",
                    Url = url
                });
            }
            else
            {
                var xFrameOptions = response.Headers.GetValues("X-Frame-Options").FirstOrDefault();
                if (!string.IsNullOrEmpty(xFrameOptions))
                {
                    var upperValue = xFrameOptions.ToUpper();

                    // Check for ALLOW-FROM (deprecated and not widely supported)
                    if (upperValue.StartsWith("ALLOW-FROM"))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Deprecated X-Frame-Options Value",
                            Description = "X-Frame-Options uses deprecated ALLOW-FROM directive, which is not supported by most browsers.",
                            Severity = Severity.Low,
                            Evidence = $"X-Frame-Options: {xFrameOptions}",
                            Remediation = "Use Content-Security-Policy frame-ancestors directive instead of X-Frame-Options ALLOW-FROM.",
                            Url = url
                        });
                    }
                }
            }

            return vulnerabilities;
        }

        private List<Vulnerability> CheckCspFrameAncestors(System.Net.Http.HttpResponseMessage response, string url)
        {
            var vulnerabilities = new List<Vulnerability>();

            var hasCsp = response.Headers.Contains("Content-Security-Policy");
            var hasCspReportOnly = response.Headers.Contains("Content-Security-Policy-Report-Only");

            if (!hasCsp && !hasCspReportOnly)
            {
                // Only report missing CSP if X-Frame-Options is also missing
                if (!response.Headers.Contains("X-Frame-Options"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "No Frame Protection",
                        Description = "Neither X-Frame-Options nor Content-Security-Policy frame-ancestors is set.",
                        Severity = Severity.Medium,
                        Evidence = "No clickjacking protection headers found",
                        Remediation = "Implement either X-Frame-Options or Content-Security-Policy frame-ancestors directive.",
                        Url = url
                    });
                }
            }
            else
            {
                var cspHeader = hasCsp ? "Content-Security-Policy" : "Content-Security-Policy-Report-Only";
                var cspValue = response.Headers.GetValues(cspHeader).FirstOrDefault();

                if (!string.IsNullOrEmpty(cspValue))
                {
                    // Check for frame-ancestors directive
                    if (!cspValue.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))
                    {
                        // CSP exists but no frame-ancestors
                        if (!response.Headers.Contains("X-Frame-Options"))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "CSP Without Frame Protection",
                                Description = "Content-Security-Policy exists but does not include frame-ancestors directive, and X-Frame-Options is missing.",
                                Severity = Severity.Medium,
                                Evidence = $"{cspHeader} present but no frame-ancestors directive",
                                Remediation = "Add frame-ancestors directive to CSP or implement X-Frame-Options header.",
                                Url = url
                            });
                        }
                    }
                    else
                    {
                        // Check for unsafe frame-ancestors values
                        var frameAncestorsMatch = Regex.Match(cspValue, @"frame-ancestors\s+([^;]+)", RegexOptions.IgnoreCase);
                        if (frameAncestorsMatch.Success)
                        {
                            var frameAncestorsValue = frameAncestorsMatch.Groups[1].Value.Trim();

                            if (frameAncestorsValue.Contains("*") && !frameAncestorsValue.Contains("'none'"))
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Weak Frame-Ancestors Policy",
                                    Description = "CSP frame-ancestors uses wildcard (*), allowing any site to frame the application.",
                                    Severity = Severity.Medium,
                                    Evidence = $"frame-ancestors {frameAncestorsValue}",
                                    Remediation = "Restrict frame-ancestors to specific trusted domains or use 'self' or 'none'.",
                                    Url = url
                                });
                            }
                        }
                    }

                    // Warn if only Report-Only mode
                    if (hasCspReportOnly && !hasCsp)
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "CSP in Report-Only Mode",
                            Description = "Content-Security-Policy is in report-only mode and not enforced.",
                            Severity = Severity.Low,
                            Evidence = "Content-Security-Policy-Report-Only header found",
                            Remediation = "Change from Content-Security-Policy-Report-Only to Content-Security-Policy to enforce the policy.",
                            Url = url
                        });
                    }
                }
            }

            return vulnerabilities;
        }

        private async Task<List<Vulnerability>> CheckFrameBustingCode(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var response = await context.HttpClient.GetAsync(context.Target.Url);
                var content = await response.Content.ReadAsStringAsync();

                // Look for common frame-busting patterns
                var frameBustingPatterns = new[]
                {
                    @"if\s*\(\s*top\s*!=\s*self\s*\)",
                    @"if\s*\(\s*top\.location\s*!=\s*self\.location\s*\)",
                    @"if\s*\(\s*parent\.frames\.length\s*>\s*0\s*\)",
                    @"if\s*\(\s*window\s*!=\s*top\s*\)"
                };

                var hasFrameBusting = frameBustingPatterns.Any(pattern =>
                    Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));

                // If frame-busting is used but no proper headers
                if (hasFrameBusting && 
                    !response.Headers.Contains("X-Frame-Options") &&
                    !response.Headers.Contains("Content-Security-Policy"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Relying on JavaScript Frame-Busting",
                        Description = "Application relies on JavaScript frame-busting code instead of proper HTTP headers. Frame-busting can be bypassed.",
                        Severity = Severity.Low,
                        Evidence = "JavaScript frame-busting code detected without proper headers",
                        Remediation = "Use X-Frame-Options or CSP frame-ancestors headers instead of or in addition to JavaScript frame-busting.",
                        Url = context.Target.Url
                    });
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
