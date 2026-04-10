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
/// Detects Server-Side Request Forgery (SSRF) vulnerabilities where user input
/// controls server-side HTTP requests targeting internal resources.
/// </summary>
public class SsrfScanner : IScannerModule
{
    public string Name => "SsrfScanner";
    public string Description => "Detects Server-Side Request Forgery (SSRF) by testing URL parameters for internal resource access.";

    private static readonly List<string> UrlParameters =
    [
        "url", "uri", "path", "file", "page", "src", "source",
        "link", "href", "redirect", "callback", "proxy", "fetch",
        "endpoint", "host", "site", "feed", "load", "resource"
    ];

    private static readonly List<string> SsrfPayloads =
    [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",   // AWS IMDS
        "http://metadata.google.internal/",             // GCP metadata
        "http://169.254.169.254/metadata/instance",     // Azure IMDS
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:25",
        // Bypass techniques
        "http://0177.0.0.1",           // Octal
        "http://0x7f000001",           // Hex
        "http://2130706433",           // Decimal
        "http://127.1",               // Short form
        "http://127.0.0.1.nip.io"     // DNS rebinding
    ];

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // Check for URL parameters that might be used for SSRF
            var paramVulns = await TestUrlParametersAsync(context);
            vulnerabilities.AddRange(paramVulns);

            // Check response for internal IP/hostname leakage (passive)
            var leakVulns = await CheckResponseForInternalLeakageAsync(context);
            vulnerabilities.AddRange(leakVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"SSRF Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> TestUrlParametersAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();
        var baseUrl = context.Target.Url;

        foreach (var param in UrlParameters.Take(8))
        {
            foreach (var payload in SsrfPayloads.Take(6))
            {
                try
                {
                    var separator = baseUrl.Contains('?') ? "&" : "?";
                    var testUrl = $"{baseUrl}{separator}{param}={HttpUtility.UrlEncode(payload)}";

                    var response = await context.HttpClient.GetAsync(testUrl);
                    var content = await response.Content.ReadAsStringAsync();

                    // Check if the response indicates the server attempted to access the internal resource
                    if (DetectSsrfSuccess(content, payload, response))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Server-Side Request Forgery (SSRF)",
                            Description = "The application appears to make server-side requests using user-controllable input. An attacker can abuse this to access internal services, cloud metadata endpoints, or perform port scanning from the server.",
                            Severity = Severity.Critical,
                            Evidence = $"Parameter: {param}\nPayload: {payload}\nStatus: {(int)response.StatusCode}",
                            Remediation = "Validate and sanitize all user-supplied URLs. Implement allowlists for permitted domains. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x). Disable unnecessary URL schemes (file://, dict://, gopher://).",
                            Url = testUrl,
                            OwaspCategory = "A10:2021 - Server-Side Request Forgery",
                            CweId = "CWE-918",
                            CvssScore = "9.1"
                        });
                        return vulnerabilities; // One finding is enough
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

    private static bool DetectSsrfSuccess(string content, string payload, HttpResponseMessage response)
    {
        // Look for indicators that the server fetched the resource
        if (payload.Contains("169.254.169.254") && content.Contains("ami-id", StringComparison.OrdinalIgnoreCase))
            return true;
        if (payload.Contains("metadata.google") && content.Contains("project-id", StringComparison.OrdinalIgnoreCase))
            return true;
        if (payload.Contains("file:///etc/passwd") && content.Contains("root:", StringComparison.OrdinalIgnoreCase))
            return true;
        if (payload.Contains("127.0.0.1") && response.IsSuccessStatusCode &&
            content.Length > 0 && !content.Contains("error", StringComparison.OrdinalIgnoreCase))
            return false; // Too many false positives on generic 200 OK

        return false;
    }

    private async Task<List<Vulnerability>> CheckResponseForInternalLeakageAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            var response = await context.HttpClient.GetAsync(context.Target.Url);
            var content = await response.Content.ReadAsStringAsync();

            // Check for internal IP addresses in response body
            var internalIpPattern = @"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b";
            var matches = Regex.Matches(content, internalIpPattern);

            if (matches.Count > 0)
            {
                var uniqueIps = matches.Cast<Match>().Select(m => m.Value).Distinct().Take(5);
                vulnerabilities.Add(new Vulnerability
                {
                    Name = "Internal IP Address Disclosure",
                    Description = "Internal/private IP addresses found in the response body. This can help an attacker map the internal network topology.",
                    Severity = Severity.Low,
                    Evidence = $"Internal IPs found: {string.Join(", ", uniqueIps)}",
                    Remediation = "Remove internal IP addresses from public responses. Review application code and server configuration for information leakage.",
                    Url = context.Target.Url,
                    OwaspCategory = "A01:2021 - Broken Access Control",
                    CweId = "CWE-200",
                    CvssScore = "3.7"
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
