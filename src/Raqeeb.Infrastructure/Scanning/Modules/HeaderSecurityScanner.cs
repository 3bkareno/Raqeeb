using System.Collections.Generic;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class HeaderSecurityScanner : IScannerModule
    {
        public string Name => "HeaderSecurityScanner";
        public string Description => "Checks for missing or misconfigured security headers.";

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            try
            {
                var response = await context.HttpClient.GetAsync(context.Target.Url);
                var url = context.Target.Url;
                
                if (!response.Headers.Contains("X-Content-Type-Options"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing X-Content-Type-Options",
                        Description = "The X-Content-Type-Options header is missing. This header prevents MIME-sniffing attacks where the browser guesses the content type.",
                        Severity = Severity.Low,
                        Remediation = "Add 'X-Content-Type-Options: nosniff' header to all responses.",
                        Url = url,
                        ModuleName = Name,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-16",
                        CvssScore = "3.7"
                    });
                }

                if (!response.Headers.Contains("Strict-Transport-Security"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing HSTS",
                        Description = "HTTP Strict Transport Security (HSTS) header is missing. This allows man-in-the-middle and protocol downgrade attacks.",
                        Severity = Severity.Medium,
                        Remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                        Url = url,
                        ModuleName = Name,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-319",
                        CvssScore = "5.3"
                    });
                }

                if (!response.Headers.Contains("X-Frame-Options") && !response.Content.Headers.Contains("Content-Security-Policy"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing X-Frame-Options",
                        Description = "The X-Frame-Options header is missing. This allows clickjacking attacks where your site can be embedded in an iframe.",
                        Severity = Severity.Medium,
                        Remediation = "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
                        Url = url,
                        ModuleName = Name,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-1021",
                        CvssScore = "4.7"
                    });
                }

                // Check Content-Security-Policy
                if (!response.Content.Headers.Contains("Content-Security-Policy"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing Content-Security-Policy",
                        Description = "Content-Security-Policy (CSP) header is missing. CSP helps prevent XSS, clickjacking, and other code injection attacks.",
                        Severity = Severity.High,
                        Remediation = "Add 'Content-Security-Policy' header with appropriate directives, e.g., 'default-src 'self''.",
                        Url = url,
                        ModuleName = Name,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-693",
                        CvssScore = "6.1"
                    });
                }

                // Check X-XSS-Protection
                if (!response.Headers.Contains("X-XSS-Protection"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing X-XSS-Protection",
                        Description = "The X-XSS-Protection header is missing. This header enables the browser's XSS filter.",
                        Severity = Severity.Low,
                        Remediation = "Add 'X-XSS-Protection: 1; mode=block' header.",
                        Url = url,
                        ModuleName = Name,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-693",
                        CvssScore = "3.7"
                    });
                }
                else if (response.Headers.TryGetValues("X-XSS-Protection", out var xssValues))
                {
                    var value = string.Join(",", xssValues);
                    if (value.Contains("0"))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "X-XSS-Protection Disabled",
                            Description = "The X-XSS-Protection header is set to 0, which disables the browser's XSS filter.",
                            Severity = Severity.Medium,
                            Remediation = "Change to 'X-XSS-Protection: 1; mode=block'.",
                            Url = url,
                            ModuleName = Name,
                            OwaspCategory = "A05:2021 - Security Misconfiguration",
                            CweId = "CWE-693",
                            CvssScore = "5.3"
                        });
                    }
                }

                // Check Referrer-Policy
                if (!response.Headers.Contains("Referrer-Policy"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing Referrer-Policy",
                        Description = "The Referrer-Policy header is missing. This can leak sensitive information in the URL.",
                        Severity = Severity.Low,
                        Remediation = "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' header.",
                        Url = url,
                        ModuleName = Name,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-116",
                        CvssScore = "3.7"
                    });
                }

                // Check Permissions-Policy (formerly Feature-Policy)
                if (!response.Headers.Contains("Permissions-Policy") && !response.Headers.Contains("Feature-Policy"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing Permissions-Policy",
                        Description = "The Permissions-Policy header is missing. This allows all browser features by default.",
                        Severity = Severity.Low,
                        Remediation = "Add 'Permissions-Policy' header to control browser features, e.g., 'geolocation=(), camera=()'.",
                        Url = url,
                        ModuleName = Name,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-16",
                        CvssScore = "3.7"
                    });
                }

                // Check for Server header disclosure
                if (response.Headers.Contains("Server"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Server Version Disclosure",
                        Description = "The Server header exposes server software and version information, which can help attackers.",
                        Severity = Severity.Info,
                        Remediation = "Remove or obfuscate the 'Server' header in your web server configuration.",
                        Url = url,
                        ModuleName = Name,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-200",
                        CvssScore = "0.0"
                    });
                }

                // Check for X-Powered-By header disclosure
                if (response.Headers.Contains("X-Powered-By"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Technology Disclosure (X-Powered-By)",
                        Description = "The X-Powered-By header exposes technology stack information.",
                        Severity = Severity.Info,
                        Remediation = "Remove the 'X-Powered-By' header from your application configuration.",
                        Url = url,
                        ModuleName = Name,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-200",
                        CvssScore = "0.0"
                    });
                }

                // Check for insecure cookies
                if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
                {
                    foreach (var cookie in cookies)
                    {
                        if (!cookie.Contains("Secure", System.StringComparison.OrdinalIgnoreCase))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "Cookie Without Secure Flag",
                                Description = "One or more cookies are set without the 'Secure' flag. This allows cookies to be sent over HTTP.",
                                Severity = Severity.Medium,
                                Remediation = "Add 'Secure' flag to all cookies in HTTPS environments.",
                                Url = url,
                                ModuleName = Name,
                                OwaspCategory = "A02:2021 - Cryptographic Failures",
                                CweId = "CWE-614",
                                CvssScore = "5.3"
                            });
                            break;
                        }
                    }

                    foreach (var cookie in cookies)
                    {
                        if (!cookie.Contains("HttpOnly", System.StringComparison.OrdinalIgnoreCase))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "Cookie Without HttpOnly Flag",
                                Description = "One or more cookies are set without the 'HttpOnly' flag. This allows JavaScript to access cookies.",
                                Severity = Severity.Medium,
                                Remediation = "Add 'HttpOnly' flag to cookies that don't need JavaScript access.",
                                Url = url,
                                ModuleName = Name,
                                OwaspCategory = "A05:2021 - Security Misconfiguration",
                                CweId = "CWE-1004",
                                CvssScore = "5.3"
                            });
                            break;
                        }
                    }

                    foreach (var cookie in cookies)
                    {
                        if (!cookie.Contains("SameSite", System.StringComparison.OrdinalIgnoreCase))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "Cookie Without SameSite Attribute",
                                Description = "One or more cookies are set without the 'SameSite' attribute. This makes the site vulnerable to CSRF attacks.",
                                Severity = Severity.Medium,
                                Remediation = "Add 'SameSite=Strict' or 'SameSite=Lax' to cookies.",
                                Url = url,
                                ModuleName = Name,
                                OwaspCategory = "A05:2021 - Security Misconfiguration",
                                CweId = "CWE-1275",
                                CvssScore = "4.7"
                            });
                            break;
                        }
                    }
                }
            }
            catch
            {
                // Log error or report connectivity issue
            }

            return vulnerabilities;
        }
    }
}

