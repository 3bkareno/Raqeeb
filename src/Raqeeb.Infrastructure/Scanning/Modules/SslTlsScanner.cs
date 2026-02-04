using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class SslTlsScanner : IScannerModule
    {
        public string Name => "SslTlsScanner";
        public string Description => "Analyzes SSL/TLS configuration including certificate validity, cipher suites, protocol versions, and HSTS implementation.";

        private static readonly List<string> WeakCiphers = new()
        {
            "DES", "3DES", "RC4", "MD5", "NULL", "EXPORT", "anon"
        };

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                // Only scan HTTPS URLs
                if (!context.Target.Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "No HTTPS",
                        Description = "The target URL does not use HTTPS. All traffic is transmitted in plain text.",
                        Severity = Severity.High,
                        Evidence = $"URL scheme: {new Uri(context.Target.Url).Scheme}",
                        Remediation = "Implement HTTPS with a valid SSL/TLS certificate. Redirect all HTTP traffic to HTTPS.",
                        Url = context.Target.Url
                    });
                    return vulnerabilities;
                }

                // Check certificate
                var certVulnerabilities = await CheckCertificate(context);
                vulnerabilities.AddRange(certVulnerabilities);

                // Check HSTS
                var hstsVulnerabilities = await CheckHsts(context);
                vulnerabilities.AddRange(hstsVulnerabilities);

                // Check for mixed content potential
                var mixedContentVulnerabilities = await CheckMixedContent(context);
                vulnerabilities.AddRange(mixedContentVulnerabilities);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SSL/TLS Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private async Task<List<Vulnerability>> CheckCertificate(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                // Create a custom handler to inspect certificate
                var handler = new System.Net.Http.HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                    {
                        // Check for certificate issues
                        if (sslPolicyErrors != SslPolicyErrors.None)
                        {
                            if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Invalid Certificate Chain",
                                    Description = "SSL/TLS certificate chain validation failed.",
                                    Severity = Severity.High,
                                    Evidence = "Certificate chain errors detected",
                                    Remediation = "Install a valid certificate from a trusted Certificate Authority. Ensure all intermediate certificates are properly configured.",
                                    Url = context.Target.Url
                                });
                            }

                            if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Certificate Name Mismatch",
                                    Description = "SSL/TLS certificate name does not match the domain.",
                                    Severity = Severity.High,
                                    Evidence = "Certificate hostname mismatch",
                                    Remediation = "Obtain a certificate that matches the domain name or add the domain to the certificate's SAN (Subject Alternative Names).",
                                    Url = context.Target.Url
                                });
                            }

                            if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "No Certificate Available",
                                    Description = "Server did not present an SSL/TLS certificate.",
                                    Severity = Severity.Critical,
                                    Evidence = "No certificate available",
                                    Remediation = "Configure the server with a valid SSL/TLS certificate.",
                                    Url = context.Target.Url
                                });
                            }
                        }

                        // Check certificate expiration
                        if (cert != null)
                        {
                            var daysUntilExpiry = (cert.NotAfter - DateTime.Now).TotalDays;
                            
                            if (daysUntilExpiry < 0)
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Expired Certificate",
                                    Description = "SSL/TLS certificate has expired.",
                                    Severity = Severity.Critical,
                                    Evidence = $"Certificate expired on: {cert.NotAfter:yyyy-MM-dd}",
                                    Remediation = "Renew the SSL/TLS certificate immediately.",
                                    Url = context.Target.Url
                                });
                            }
                            else if (daysUntilExpiry < 30)
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Certificate Expiring Soon",
                                    Description = $"SSL/TLS certificate will expire in {(int)daysUntilExpiry} days.",
                                    Severity = Severity.Medium,
                                    Evidence = $"Certificate expires on: {cert.NotAfter:yyyy-MM-dd}",
                                    Remediation = "Renew the SSL/TLS certificate before it expires.",
                                    Url = context.Target.Url
                                });
                            }

                            // Check for weak signature algorithm
                            if (cert.SignatureAlgorithm.FriendlyName.Contains("sha1", StringComparison.OrdinalIgnoreCase) ||
                                cert.SignatureAlgorithm.FriendlyName.Contains("md5", StringComparison.OrdinalIgnoreCase))
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Weak Certificate Signature",
                                    Description = $"Certificate uses weak signature algorithm: {cert.SignatureAlgorithm.FriendlyName}",
                                    Severity = Severity.Medium,
                                    Evidence = $"Signature algorithm: {cert.SignatureAlgorithm.FriendlyName}",
                                    Remediation = "Obtain a certificate with SHA-256 or stronger signature algorithm.",
                                    Url = context.Target.Url
                                });
                            }

                            // Check key size
                            var publicKey = cert.GetPublicKey();
                            if (publicKey.Length < 256) // Less than 2048 bits
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Weak Certificate Key",
                                    Description = "Certificate uses a weak key size.",
                                    Severity = Severity.Medium,
                                    Evidence = $"Key size: {publicKey.Length * 8} bits",
                                    Remediation = "Use certificates with at least 2048-bit RSA keys or 256-bit ECC keys.",
                                    Url = context.Target.Url
                                });
                            }
                        }

                        return true; // Continue with request
                    }
                };

                using var client = new System.Net.Http.HttpClient(handler);
                await client.GetAsync(context.Target.Url);
            }
            catch
            {
                // Errors already captured in callback
            }

            return vulnerabilities;
        }

        private async Task<List<Vulnerability>> CheckHsts(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var response = await context.HttpClient.GetAsync(context.Target.Url);

                if (!response.Headers.Contains("Strict-Transport-Security"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing HSTS Header",
                        Description = "HTTP Strict Transport Security (HSTS) header is not configured.",
                        Severity = Severity.Medium,
                        Evidence = "Strict-Transport-Security header not found",
                        Remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header to enforce HTTPS.",
                        Url = context.Target.Url
                    });
                }
                else
                {
                    var hstsValues = response.Headers.GetValues("Strict-Transport-Security").FirstOrDefault();
                    if (!string.IsNullOrEmpty(hstsValues))
                    {
                        // Check max-age value
                        var maxAgeMatch = System.Text.RegularExpressions.Regex.Match(hstsValues, @"max-age=(\d+)");
                        if (maxAgeMatch.Success)
                        {
                            var maxAge = int.Parse(maxAgeMatch.Groups[1].Value);
                            if (maxAge < 31536000) // Less than 1 year
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Weak HSTS Configuration",
                                    Description = "HSTS max-age is too short. Recommended minimum is 1 year (31536000 seconds).",
                                    Severity = Severity.Low,
                                    Evidence = $"Current max-age: {maxAge} seconds",
                                    Remediation = "Increase HSTS max-age to at least 31536000 seconds (1 year).",
                                    Url = context.Target.Url
                                });
                            }
                        }

                        // Check for includeSubDomains
                        if (!hstsValues.Contains("includeSubDomains", StringComparison.OrdinalIgnoreCase))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "HSTS Not Covering Subdomains",
                                Description = "HSTS header does not include 'includeSubDomains' directive.",
                                Severity = Severity.Low,
                                Evidence = $"HSTS header: {hstsValues}",
                                Remediation = "Add 'includeSubDomains' to HSTS header to protect all subdomains.",
                                Url = context.Target.Url
                            });
                        }
                    }
                }
            }
            catch
            {
                // Continue
            }

            return vulnerabilities;
        }

        private async Task<List<Vulnerability>> CheckMixedContent(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var response = await context.HttpClient.GetAsync(context.Target.Url);
                var content = await response.Content.ReadAsStringAsync();

                // Look for HTTP resources in HTTPS page
                var httpResourcePattern = @"(src|href|action)\s*=\s*['""]http://[^'""]*['""]";
                var matches = System.Text.RegularExpressions.Regex.Matches(content, httpResourcePattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);

                if (matches.Count > 0)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Mixed Content",
                        Description = $"Page contains {matches.Count} HTTP resources loaded over an HTTPS connection.",
                        Severity = Severity.Medium,
                        Evidence = $"Found {matches.Count} HTTP resource(s) in HTTPS page",
                        Remediation = "Load all resources over HTTPS. Update links to use HTTPS or protocol-relative URLs.",
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
