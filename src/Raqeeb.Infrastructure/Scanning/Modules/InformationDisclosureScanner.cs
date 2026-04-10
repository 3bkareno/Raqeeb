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
/// Detects information disclosure, sensitive data exposure, and technology stack leakage.
/// </summary>
public class InformationDisclosureScanner : IScannerModule
{
    public string Name => "InformationDisclosureScanner";
    public string Description => "Detects information disclosure including stack traces, debug pages, sensitive files, technology leakage, and error messages.";

    private static readonly string[] SensitivePaths =
    [
        "/elmah.axd", "/trace.axd", "/server-status", "/server-info",
        "/.env", "/.env.bak", "/.env.local", "/.env.production",
        "/.git/HEAD", "/.git/config", "/.svn/entries",
        "/web.config", "/web.config.bak", "/appsettings.json",
        "/wp-config.php.bak", "/config.php.bak",
        "/.DS_Store", "/Thumbs.db",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/.well-known/security.txt",
        "/phpinfo.php", "/info.php",
        "/debug", "/debug/default/view",
        "/_profiler", "/_debugbar",
        "/actuator", "/actuator/health", "/actuator/env",
        "/swagger/v1/swagger.json", "/openapi.json"
    ];

    private static readonly Regex EmailPattern = new(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", RegexOptions.Compiled);
    private static readonly Regex CreditCardPattern = new(@"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", RegexOptions.Compiled);
    private static readonly Regex SsnPattern = new(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled);
    private static readonly Regex ApiKeyPattern = new(@"(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*['""]?([a-zA-Z0-9_\-]{16,})['""]?", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // Check response headers for technology disclosure
            var headerVulns = await CheckTechnologyDisclosureAsync(context);
            vulnerabilities.AddRange(headerVulns);

            // Check for sensitive data in response body
            var dataVulns = await CheckSensitiveDataInBodyAsync(context);
            vulnerabilities.AddRange(dataVulns);

            // Check for exposed sensitive files
            var fileVulns = await CheckSensitiveFilesAsync(context);
            vulnerabilities.AddRange(fileVulns);

            // Check for error messages and stack traces
            var errorVulns = await CheckErrorDisclosureAsync(context);
            vulnerabilities.AddRange(errorVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Information Disclosure Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> CheckTechnologyDisclosureAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        var response = await context.HttpClient.GetAsync(context.Target.Url);
        var disclosedHeaders = new List<string>();

        void CheckHeader(string headerName)
        {
            if (response.Headers.TryGetValues(headerName, out var values))
                disclosedHeaders.Add($"{headerName}: {string.Join(", ", values)}");
            if (response.Content.Headers.TryGetValues(headerName, out var cValues))
                disclosedHeaders.Add($"{headerName}: {string.Join(", ", cValues)}");
        }

        CheckHeader("Server");
        CheckHeader("X-Powered-By");
        CheckHeader("X-AspNet-Version");
        CheckHeader("X-AspNetMvc-Version");
        CheckHeader("X-Runtime");
        CheckHeader("X-Generator");

        if (disclosedHeaders.Count > 0)
        {
            vulnerabilities.Add(new Vulnerability
            {
                Name = "Technology Stack Disclosure",
                Description = "The server reveals technology stack information through HTTP headers. This helps attackers identify known vulnerabilities for specific versions.",
                Severity = Severity.Low,
                Evidence = string.Join("\n", disclosedHeaders),
                Remediation = "Remove or suppress technology-identifying headers. Configure the web server to omit Server, X-Powered-By, X-AspNet-Version headers.",
                Url = context.Target.Url,
                OwaspCategory = "A05:2021 - Security Misconfiguration",
                CweId = "CWE-200",
                CvssScore = "3.7"
            });
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> CheckSensitiveDataInBodyAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        var response = await context.HttpClient.GetAsync(context.Target.Url);
        var content = await response.Content.ReadAsStringAsync();

        // Check for email addresses (informational)
        var emails = EmailPattern.Matches(content).Cast<Match>().Select(m => m.Value).Distinct().Take(5).ToList();
        if (emails.Count > 0)
        {
            vulnerabilities.Add(new Vulnerability
            {
                Name = "Email Address Disclosure",
                Description = "Email addresses found in the page source. These can be harvested for phishing or spam campaigns.",
                Severity = Severity.Info,
                Evidence = $"Emails found: {string.Join(", ", emails)}",
                Remediation = "Obfuscate email addresses on public pages. Use contact forms instead of displaying raw email addresses.",
                Url = context.Target.Url,
                OwaspCategory = "A01:2021 - Broken Access Control",
                CweId = "CWE-200",
                CvssScore = "0.0"
            });
        }

        // Check for API keys/secrets in HTML
        var apiKeys = ApiKeyPattern.Matches(content);
        if (apiKeys.Count > 0)
        {
            vulnerabilities.Add(new Vulnerability
            {
                Name = "Potential API Key/Secret Exposure",
                Description = "Potential API keys or secrets were found embedded in the page source code.",
                Severity = Severity.High,
                Evidence = $"Found {apiKeys.Count} potential key/secret pattern(s) in HTML source",
                Remediation = "Never embed API keys or secrets in client-side code. Use server-side environment variables and backend proxies.",
                Url = context.Target.Url,
                OwaspCategory = "A02:2021 - Cryptographic Failures",
                CweId = "CWE-312",
                CvssScore = "7.5"
            });
        }

        // Check for HTML comments with sensitive info
        var comments = Regex.Matches(content, @"<!--(.*?)-->", RegexOptions.Singleline);
        foreach (Match comment in comments)
        {
            var text = comment.Groups[1].Value.ToLowerInvariant();
            if (text.Contains("password") || text.Contains("secret") || text.Contains("todo") ||
                text.Contains("fixme") || text.Contains("hack") || text.Contains("bug") ||
                text.Contains("admin") || text.Contains("debug"))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Name = "Sensitive Information in HTML Comments",
                    Description = "HTML comments contain potentially sensitive information such as passwords, debug notes, or internal references.",
                    Severity = Severity.Low,
                    Evidence = $"Comment: {comment.Value[..Math.Min(comment.Value.Length, 200)]}",
                    Remediation = "Remove all sensitive comments from production HTML. Use server-side comments that are not sent to the client.",
                    Url = context.Target.Url,
                    OwaspCategory = "A05:2021 - Security Misconfiguration",
                    CweId = "CWE-615",
                    CvssScore = "3.7"
                });
                break; // One finding is enough
            }
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> CheckSensitiveFilesAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();
        var uri = new Uri(context.Target.Url);
        var baseUrl = $"{uri.Scheme}://{uri.Authority}";

        foreach (var path in SensitivePaths.Take(20))
        {
            try
            {
                var response = await context.HttpClient.GetAsync(baseUrl + path);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    if (content.Length > 0 && !IsGenericErrorPage(content))
                    {
                        var (severity, description) = ClassifySensitiveFile(path, content);
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = $"Sensitive File Exposed: {path}",
                            Description = description,
                            Severity = severity,
                            Evidence = $"Path: {path}\nStatus: {(int)response.StatusCode}\nContent-Length: {content.Length}",
                            Remediation = "Remove or restrict access to sensitive files. Configure the web server to deny access to configuration files, version control directories, and backup files.",
                            Url = baseUrl + path,
                            OwaspCategory = "A05:2021 - Security Misconfiguration",
                            CweId = "CWE-538",
                            CvssScore = severity >= Severity.High ? "7.5" : "5.3"
                        });
                    }
                }
            }
            catch
            {
                // Continue
            }
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> CheckErrorDisclosureAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        // Trigger an error by requesting a non-existent page
        var errorUrls = new[]
        {
            context.Target.Url + "/nonexistent-" + Guid.NewGuid().ToString()[..8],
            context.Target.Url + "/'",
            context.Target.Url + "/%00"
        };

        foreach (var errorUrl in errorUrls)
        {
            try
            {
                var response = await context.HttpClient.GetAsync(errorUrl);
                var content = await response.Content.ReadAsStringAsync();

                // Check for stack traces
                if (Regex.IsMatch(content, @"at\s+\w+\.\w+.*\sin\s+.+:\s*line\s+\d+", RegexOptions.IgnoreCase) ||
                    content.Contains("System.Exception", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("Stack Trace:", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("Traceback (most recent call last)", StringComparison.OrdinalIgnoreCase))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Stack Trace / Debug Information Disclosure",
                        Description = "The application exposes detailed error messages and stack traces to users. This reveals internal implementation details, file paths, and technology stack.",
                        Severity = Severity.Medium,
                        Evidence = $"Stack trace detected in error response at {errorUrl}",
                        Remediation = "Disable detailed error messages in production. Implement custom error pages. Use proper logging to capture errors server-side.",
                        Url = errorUrl,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-209",
                        CvssScore = "5.3"
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

    private static bool IsGenericErrorPage(string content)
    {
        return content.Contains("404") && content.Length < 500;
    }

    private static (Severity, string) ClassifySensitiveFile(string path, string content)
    {
        if (path.Contains(".env"))
            return (Severity.Critical, "Environment configuration file exposed. Likely contains database credentials, API keys, and secrets.");
        if (path.Contains(".git"))
            return (Severity.High, "Git repository metadata exposed. Source code and commit history can be reconstructed.");
        if (path.Contains("config") || path.Contains("appsettings"))
            return (Severity.High, "Application configuration file exposed. May contain connection strings and credentials.");
        if (path.Contains("swagger") || path.Contains("openapi"))
            return (Severity.Low, "API documentation endpoint exposed. Review for sensitive endpoint disclosure.");
        if (path.Contains("actuator"))
            return (Severity.High, "Spring Boot Actuator endpoints exposed. May reveal environment variables and configuration.");
        if (path.Contains("phpinfo"))
            return (Severity.Medium, "PHP information page exposed. Reveals server configuration, loaded modules, and environment variables.");
        if (path.Contains("backup") || path.Contains(".bak"))
            return (Severity.Critical, "Backup file exposed. May contain application source code or database dumps.");

        return (Severity.Medium, $"Sensitive file exposed at {path}. Review content for sensitive information.");
    }
}
