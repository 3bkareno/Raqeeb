using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class CorsScanner : IScannerModule
    {
        public string Name => "CorsScanner";
        public string Description => "Detects CORS (Cross-Origin Resource Sharing) misconfigurations that could lead to security vulnerabilities.";

        private static readonly List<string> TestOrigins = new()
        {
            "https://evil.com",
            "https://attacker.com",
            "null"
        };

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                // Test with normal request first
                var normalResponse = await context.HttpClient.GetAsync(context.Target.Url);
                var normalVulns = CheckCorsHeaders(normalResponse, context.Target.Url, null);
                vulnerabilities.AddRange(normalVulns);

                // Test with malicious origins
                foreach (var testOrigin in TestOrigins.Take(2))
                {
                    var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, context.Target.Url);
                    request.Headers.Add("Origin", testOrigin);

                    var response = await context.HttpClient.SendAsync(request);
                    var originVulns = CheckCorsHeaders(response, context.Target.Url, testOrigin);
                    vulnerabilities.AddRange(originVulns);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"CORS Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private List<Vulnerability> CheckCorsHeaders(System.Net.Http.HttpResponseMessage response, string url, string? testedOrigin)
        {
            var vulnerabilities = new List<Vulnerability>();

            // Check Access-Control-Allow-Origin
            if (response.Headers.Contains("Access-Control-Allow-Origin"))
            {
                var allowedOrigins = response.Headers.GetValues("Access-Control-Allow-Origin").ToList();

                foreach (var origin in allowedOrigins)
                {
                    // Wildcard origin
                    if (origin == "*")
                    {
                        // Check if credentials are allowed (very dangerous combination)
                        if (response.Headers.Contains("Access-Control-Allow-Credentials"))
                        {
                            var allowCredentials = response.Headers.GetValues("Access-Control-Allow-Credentials")
                                .Any(v => v.Equals("true", StringComparison.OrdinalIgnoreCase));

                            if (allowCredentials)
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Critical CORS Misconfiguration",
                                    Description = "Server allows credentials with wildcard origin (*). This is a critical security vulnerability.",
                                    Severity = Severity.Critical,
                                    Evidence = "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                                    Remediation = "Never use wildcard origin with credentials. Specify exact trusted origins or remove credentials support.",
                                    Url = url
                                });
                            }
                            else
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Overly Permissive CORS",
                                    Description = "Server allows all origins (*) to access resources via CORS.",
                                    Severity = Severity.Medium,
                                    Evidence = "Access-Control-Allow-Origin: *",
                                    Remediation = "Restrict CORS to specific trusted origins. Maintain a whitelist of allowed origins.",
                                    Url = url
                                });
                            }
                        }
                    }
                    // Null origin (can be exploited)
                    else if (origin.Equals("null", StringComparison.OrdinalIgnoreCase))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "CORS Null Origin Allowed",
                            Description = "Server explicitly allows 'null' origin, which can be exploited by attackers.",
                            Severity = Severity.High,
                            Evidence = "Access-Control-Allow-Origin: null",
                            Remediation = "Do not allow 'null' origin. Use specific trusted origins instead.",
                            Url = url
                        });
                    }
                    // Reflected origin (potential vulnerability)
                    else if (testedOrigin != null && origin.Equals(testedOrigin, StringComparison.OrdinalIgnoreCase))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "CORS Origin Reflection",
                            Description = "Server reflects the Origin header value, potentially allowing any origin to access resources.",
                            Severity = Severity.High,
                            Evidence = $"Requested Origin: {testedOrigin}\nReflected Origin: {origin}",
                            Remediation = "Implement proper origin validation. Maintain a whitelist of trusted origins instead of reflecting the request origin.",
                            Url = url
                        });
                    }
                }
            }

            // Check for dangerous methods allowed
            if (response.Headers.Contains("Access-Control-Allow-Methods"))
            {
                var methods = response.Headers.GetValues("Access-Control-Allow-Methods").FirstOrDefault();
                if (!string.IsNullOrEmpty(methods))
                {
                    var dangerousMethods = new[] { "PUT", "DELETE", "PATCH" };
                    var allowedDangerousMethods = dangerousMethods.Where(m =>
                        methods.Contains(m, StringComparison.OrdinalIgnoreCase)).ToList();

                    if (allowedDangerousMethods.Any())
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Dangerous CORS Methods Allowed",
                            Description = $"Server allows potentially dangerous HTTP methods: {string.Join(", ", allowedDangerousMethods)}",
                            Severity = Severity.Medium,
                            Evidence = $"Access-Control-Allow-Methods: {methods}",
                            Remediation = "Restrict allowed methods to only those necessary. Avoid allowing PUT, DELETE, PATCH unless required.",
                            Url = url
                        });
                    }
                }
            }

            // Check for overly permissive headers
            if (response.Headers.Contains("Access-Control-Allow-Headers"))
            {
                var headers = response.Headers.GetValues("Access-Control-Allow-Headers").FirstOrDefault();
                if (!string.IsNullOrEmpty(headers) && headers.Contains("*"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Wildcard CORS Headers",
                        Description = "Server allows all headers (*) in CORS requests.",
                        Severity = Severity.Low,
                        Evidence = "Access-Control-Allow-Headers: *",
                        Remediation = "Explicitly specify allowed headers instead of using wildcard.",
                        Url = url
                    });
                }
            }

            return vulnerabilities;
        }
    }
}
