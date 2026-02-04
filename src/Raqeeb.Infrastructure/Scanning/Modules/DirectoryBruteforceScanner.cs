using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class DirectoryBruteforceScanner : IScannerModule
    {
        public string Name => "DirectoryBruteforceScanner";
        public string Description => "Attempts to discover hidden directories and files through common path enumeration.";

        private static readonly List<string> CommonPaths = new()
        {
            "/admin", "/administrator", "/admin.php", "/admin/login",
            "/login", "/signin", "/user/login",
            "/backup", "/backups", "/.backup", "/backup.zip", "/backup.sql",
            "/.git", "/.git/config", "/.svn", "/.env",
            "/config", "/config.php", "/configuration.php",
            "/test", "/tests", "/testing",
            "/api", "/api/docs", "/swagger", "/api.json",
            "/phpmyadmin", "/phpinfo.php", "/info.php",
            "/robots.txt", "/sitemap.xml", "/.htaccess",
            "/wp-admin", "/wp-login.php", "/wp-config.php"
        };

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                var baseUri = new Uri(context.Target.Url);
                var baseUrl = $"{baseUri.Scheme}://{baseUri.Host}:{baseUri.Port}";

                foreach (var path in CommonPaths.Take(15)) // Limit for performance
                {
                    try
                    {
                        var testUrl = baseUrl + path;
                        var response = await context.HttpClient.GetAsync(testUrl);

                        // Check for successful responses or interesting status codes
                        if (response.IsSuccessStatusCode || 
                            response.StatusCode == System.Net.HttpStatusCode.Forbidden ||
                            response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                        {
                            var severity = DetermineSeverity(path, response.StatusCode);
                            var description = GetPathDescription(path, response.StatusCode);

                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "Discovered Hidden Path",
                                Description = description,
                                Severity = severity,
                                Evidence = $"Path: {path}\nStatus Code: {(int)response.StatusCode} {response.StatusCode}\nURL: {testUrl}",
                                Remediation = "Review exposed paths. Remove or properly secure sensitive directories and files. Implement proper access controls.",
                                Url = testUrl
                            });
                        }
                    }
                    catch
                    {
                        // Path not accessible, continue
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Directory Bruteforce Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private Severity DetermineSeverity(string path, System.Net.HttpStatusCode statusCode)
        {
            // High severity paths
            if (path.Contains("backup") || path.Contains(".git") || path.Contains(".env") ||
                path.Contains("config") || path.Contains("wp-config") || path.Contains(".sql"))
            {
                return statusCode == System.Net.HttpStatusCode.OK ? Severity.Critical : Severity.High;
            }

            // Medium severity paths
            if (path.Contains("admin") || path.Contains("phpmyadmin") || path.Contains("phpinfo"))
            {
                return statusCode == System.Net.HttpStatusCode.OK ? Severity.High : Severity.Medium;
            }

            // Lower severity for informational files
            if (path.Contains("robots.txt") || path.Contains("sitemap.xml"))
            {
                return Severity.Info;
            }

            return Severity.Low;
        }

        private string GetPathDescription(string path, System.Net.HttpStatusCode statusCode)
        {
            if (path.Contains("backup"))
                return $"Backup file or directory discovered ({statusCode}). May contain sensitive data.";
            
            if (path.Contains(".git") || path.Contains(".svn"))
                return $"Version control directory discovered ({statusCode}). May expose source code.";
            
            if (path.Contains(".env"))
                return $"Environment configuration file discovered ({statusCode}). Likely contains credentials.";
            
            if (path.Contains("config"))
                return $"Configuration file discovered ({statusCode}). May contain sensitive information.";
            
            if (path.Contains("admin"))
                return $"Administrative interface discovered ({statusCode}). Potential attack vector.";
            
            if (path.Contains("api"))
                return $"API endpoint discovered ({statusCode}). Review for proper authentication.";
            
            if (path.Contains("phpinfo") || path.Contains("info.php"))
                return $"PHP information page discovered ({statusCode}). Exposes system configuration.";

            return $"Hidden path discovered ({statusCode}). Review for sensitive exposure.";
        }
    }
}
