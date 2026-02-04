using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class SubdomainEnumerationScanner : IScannerModule
    {
        public string Name => "SubdomainEnumerationScanner";
        public string Description => "Attempts to discover subdomains through DNS enumeration and common subdomain patterns.";

        private static readonly List<string> CommonSubdomains = new()
        {
            "www", "mail", "webmail", "ftp", "admin", "administrator",
            "dev", "development", "test", "testing", "stage", "staging",
            "api", "app", "portal", "secure", "vpn",
            "blog", "shop", "store", "forums", "community",
            "dashboard", "panel", "cpanel", "whm",
            "cdn", "static", "assets", "media", "images",
            "beta", "alpha", "demo", "preview",
            "mobile", "m", "old", "legacy", "backup"
        };

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var uri = new Uri(context.Target.Url);
                var baseDomain = ExtractBaseDomain(uri.Host);

                if (string.IsNullOrEmpty(baseDomain))
                {
                    return vulnerabilities;
                }

                var discoveredSubdomains = new List<string>();

                // Try to resolve common subdomains
                foreach (var subdomain in CommonSubdomains.Take(15)) // Limit for performance
                {
                    var fullDomain = $"{subdomain}.{baseDomain}";
                    
                    try
                    {
                        var addresses = await Dns.GetHostAddressesAsync(fullDomain);
                        if (addresses.Length > 0)
                        {
                            discoveredSubdomains.Add(fullDomain);
                        }
                    }
                    catch
                    {
                        // Subdomain doesn't exist or couldn't resolve
                    }
                }

                // Report discovered subdomains as informational findings
                if (discoveredSubdomains.Any())
                {
                    var severity = DetermineSubdomainSeverity(discoveredSubdomains);
                    
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Subdomains Discovered",
                        Description = $"Discovered {discoveredSubdomains.Count} subdomain(s) through enumeration. These may represent additional attack surface.",
                        Severity = severity,
                        Evidence = $"Discovered subdomains:\n{string.Join("\n", discoveredSubdomains.Take(10))}",
                        Remediation = "Review discovered subdomains. Ensure all subdomains are properly secured and monitored. Remove unused subdomains.",
                        Url = context.Target.Url
                    });

                    // Check for potentially sensitive subdomains
                    var sensitiveSubdomains = discoveredSubdomains.Where(IsSensitiveSubdomain).ToList();
                    if (sensitiveSubdomains.Any())
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Sensitive Subdomains Exposed",
                            Description = $"Discovered {sensitiveSubdomains.Count} potentially sensitive subdomain(s) that may expose internal resources.",
                            Severity = Severity.Medium,
                            Evidence = $"Sensitive subdomains:\n{string.Join("\n", sensitiveSubdomains)}",
                            Remediation = "Restrict access to sensitive subdomains. Use internal DNS or VPN for development/staging/admin environments.",
                            Url = context.Target.Url
                        });
                    }

                    // Try to access discovered subdomains via HTTP/HTTPS
                    await CheckSubdomainAccess(discoveredSubdomains, vulnerabilities, context);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Subdomain Enumeration Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private string ExtractBaseDomain(string host)
        {
            var parts = host.Split('.');
            if (parts.Length >= 2)
            {
                // Simple extraction - take last two parts
                return $"{parts[^2]}.{parts[^1]}";
            }
            return host;
        }

        private bool IsSensitiveSubdomain(string subdomain)
        {
            var lower = subdomain.ToLower();
            return lower.Contains("dev") || lower.Contains("test") || lower.Contains("staging") ||
                   lower.Contains("admin") || lower.Contains("panel") || lower.Contains("backup") ||
                   lower.Contains("vpn") || lower.Contains("internal");
        }

        private Severity DetermineSubdomainSeverity(List<string> subdomains)
        {
            var hasSensitive = subdomains.Any(IsSensitiveSubdomain);
            return hasSensitive ? Severity.Medium : Severity.Info;
        }

        private async Task CheckSubdomainAccess(List<string> subdomains, List<Vulnerability> vulnerabilities, ScanContext context)
        {
            foreach (var subdomain in subdomains.Take(5)) // Limit checks
            {
                try
                {
                    // Try HTTPS first
                    var httpsUrl = $"https://{subdomain}";
                    var response = await context.HttpClient.GetAsync(httpsUrl);

                    if (response.IsSuccessStatusCode)
                    {
                        // Check if it's a development/staging environment with weak security
                        var content = await response.Content.ReadAsStringAsync();
                        if (content.Contains("development", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("staging", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("test environment", StringComparison.OrdinalIgnoreCase))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "Accessible Development Environment",
                                Description = $"Development or staging environment is publicly accessible: {subdomain}",
                                Severity = Severity.Medium,
                                Evidence = $"URL: {httpsUrl}\nEnvironment indicators found in content",
                                Remediation = "Restrict access to development/staging environments using IP whitelisting or authentication.",
                                Url = httpsUrl
                            });
                        }
                    }
                }
                catch
                {
                    // Couldn't access subdomain
                }
            }
        }
    }
}
