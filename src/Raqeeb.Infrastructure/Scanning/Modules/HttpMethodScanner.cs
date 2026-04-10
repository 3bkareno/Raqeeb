using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules;

/// <summary>
/// Detects HTTP method tampering, verb abuse, and dangerous HTTP methods allowed.
/// </summary>
public class HttpMethodScanner : IScannerModule
{
    public string Name => "HttpMethodScanner";
    public string Description => "Detects dangerous HTTP methods (PUT, DELETE, TRACE, OPTIONS) and verb-tampering vulnerabilities.";

    private static readonly string[] DangerousMethods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];
    private static readonly string[] AllMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD", "CONNECT"];

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // Check OPTIONS to see what's allowed
            var optionsVulns = await CheckOptionsMethodAsync(context);
            vulnerabilities.AddRange(optionsVulns);

            // Check TRACE method (XST vulnerability)
            var traceVulns = await CheckTraceMethodAsync(context);
            vulnerabilities.AddRange(traceVulns);

            // Check for verb tampering
            var tamperVulns = await CheckVerbTamperingAsync(context);
            vulnerabilities.AddRange(tamperVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"HTTP Method Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> CheckOptionsMethodAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            var request = new HttpRequestMessage(HttpMethod.Options, context.Target.Url);
            var response = await context.HttpClient.SendAsync(request);

            if (response.Headers.Contains("Allow"))
            {
                var allowedMethods = response.Headers.GetValues("Allow").FirstOrDefault() ?? "";
                var dangerous = DangerousMethods.Where(m =>
                    allowedMethods.Contains(m, StringComparison.OrdinalIgnoreCase)).ToList();

                if (dangerous.Count > 0)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Dangerous HTTP Methods Allowed",
                        Description = $"The server allows potentially dangerous HTTP methods: {string.Join(", ", dangerous)}. These methods could be used to modify or delete server resources.",
                        Severity = dangerous.Contains("TRACE") ? Severity.High : Severity.Medium,
                        Evidence = $"Allow: {allowedMethods}",
                        Remediation = "Disable unnecessary HTTP methods on the web server. Only allow GET, POST, and HEAD for most endpoints.",
                        Url = context.Target.Url,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-749",
                        CvssScore = "5.3"
                    });
                }
            }
        }
        catch
        {
            // OPTIONS not supported
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> CheckTraceMethodAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            var request = new HttpRequestMessage(new HttpMethod("TRACE"), context.Target.Url);
            request.Headers.Add("X-Custom-Header", "RaqeebTraceTest");
            var response = await context.HttpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                // TRACE reflects the request back—check if our header is in the body
                if (content.Contains("RaqeebTraceTest", StringComparison.OrdinalIgnoreCase))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "HTTP TRACE Method Enabled (Cross-Site Tracing)",
                        Description = "The TRACE HTTP method is enabled and reflects request headers in the response body. This can be exploited via Cross-Site Tracing (XST) to steal authentication cookies even with HttpOnly flag.",
                        Severity = Severity.High,
                        Evidence = "TRACE method returned 200 OK with reflected headers",
                        Remediation = "Disable the TRACE method on the web server. In IIS, use Request Filtering. In Apache, use TraceEnable Off.",
                        Url = context.Target.Url,
                        OwaspCategory = "A05:2021 - Security Misconfiguration",
                        CweId = "CWE-693",
                        CvssScore = "6.1"
                    });
                }
            }
        }
        catch
        {
            // TRACE not supported
        }

        return vulnerabilities;
    }

    private async Task<List<Vulnerability>> CheckVerbTamperingAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // Get a baseline 403/401 page by hitting an admin-like path
            var adminPaths = new[] { "/admin", "/dashboard", "/settings", "/api/admin" };
            foreach (var path in adminPaths)
            {
                try
                {
                    var uri = new Uri(context.Target.Url);
                    var testUrl = $"{uri.Scheme}://{uri.Authority}{path}";

                    var getResponse = await context.HttpClient.GetAsync(testUrl);

                    // If we get 403/401 on GET, try other verbs
                    if (getResponse.StatusCode == System.Net.HttpStatusCode.Forbidden ||
                        getResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        // Try bypassing with HEAD
                        var headRequest = new HttpRequestMessage(HttpMethod.Head, testUrl);
                        var headResponse = await context.HttpClient.SendAsync(headRequest);

                        if (headResponse.IsSuccessStatusCode)
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "HTTP Verb Tampering Bypass",
                                Description = $"Access control at {path} can be bypassed by changing the HTTP method. GET returns {(int)getResponse.StatusCode} but HEAD returns {(int)headResponse.StatusCode}.",
                                Severity = Severity.High,
                                Evidence = $"GET {path} ? {(int)getResponse.StatusCode}\nHEAD {path} ? {(int)headResponse.StatusCode}",
                                Remediation = "Enforce authorization consistently across all HTTP methods. Use framework-level authorization attributes.",
                                Url = testUrl,
                                OwaspCategory = "A01:2021 - Broken Access Control",
                                CweId = "CWE-650",
                                CvssScore = "7.5"
                            });
                            break;
                        }
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
