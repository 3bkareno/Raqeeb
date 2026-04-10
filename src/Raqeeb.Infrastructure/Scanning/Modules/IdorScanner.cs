using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules;

/// <summary>
/// Detects Insecure Direct Object Reference (IDOR) vulnerabilities where
/// an attacker can access resources belonging to other users by manipulating
/// object identifiers in URLs, parameters, or request bodies.
/// Covers numeric ID enumeration, GUID manipulation, HTTP verb tampering,
/// and broken object-level authorization (BOLA).
/// </summary>
public class IdorScanner : IScannerModule
{
    public string Name => "IdorScanner";
    public string Description => "Detects Insecure Direct Object Reference (IDOR) and Broken Object-Level Authorization (BOLA) via ID enumeration, verb tampering, and horizontal privilege escalation.";

    // ?? REST endpoint patterns that commonly use resource IDs ???????????????
    private static readonly Regex[] RestPatterns =
    [
        new Regex(@"/api/[^/]+/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"/users?/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"/accounts?/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"/orders?/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"/products?/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"/invoices?/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"/documents?/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"/files?/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"/items?/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex(@"/resources?/(\d+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    ];

    // ?? GUID patterns ???????????????????????????????????????????????????????
    private static readonly Regex GuidPattern = new(
        @"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // ?? Common ID parameter names ???????????????????????????????????????????
    private static readonly string[] IdParameterNames =
    [
        "id", "userId", "user_id", "accountId", "account_id",
        "orderId", "order_id", "productId", "product_id",
        "documentId", "document_id", "fileId", "file_id",
        "invoiceId", "invoice_id", "itemId", "item_id",
        "resourceId", "resource_id", "objectId", "object_id",
        "recordId", "record_id", "customerId", "customer_id"
    ];

    // ?? HTTP methods to test for verb tampering ?????????????????????????????
    private static readonly HttpMethod[] DangerousMethods =
    [
        HttpMethod.Put,
        HttpMethod.Delete,
        HttpMethod.Patch
    ];

    // ????????????????????????????????????????????????????????????????????????
    //  Entry point
    // ????????????????????????????????????????????????????????????????????????

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // 1. Discover endpoints with numeric IDs
            var numericEndpoints = DiscoverNumericIdEndpoints(context);

            // 2. Test numeric ID enumeration
            var numericVulns = await TestNumericIdEnumerationAsync(context, numericEndpoints);
            vulnerabilities.AddRange(numericVulns);

            // 3. Discover endpoints with GUIDs
            var guidEndpoints = DiscoverGuidEndpoints(context);

            // 4. Test GUID enumeration (predictable GUIDs)
            var guidVulns = await TestGuidEnumerationAsync(context, guidEndpoints);
            vulnerabilities.AddRange(guidVulns);

            // 5. Test HTTP verb tampering
            var verbVulns = await TestHttpVerbTamperingAsync(context, numericEndpoints);
            vulnerabilities.AddRange(verbVulns);

            // 6. Test query parameter ID manipulation
            var queryVulns = await TestQueryParameterIdManipulationAsync(context);
            vulnerabilities.AddRange(queryVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"IDOR Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Endpoint discovery
    // ????????????????????????????????????????????????????????????????????????

    /// <summary>
    /// Discovers endpoints with numeric IDs from crawled URLs.
    /// Returns tuples of (baseUrl, id) for enumeration testing.
    /// </summary>
    private static List<(string BaseUrl, int Id)> DiscoverNumericIdEndpoints(ScanContext context)
    {
        var endpoints = new List<(string, int)>();
        var allUrls = new List<string> { context.Target.Url };
        allUrls.AddRange(context.DiscoveredUrls);

        foreach (var url in allUrls.Take(50))
        {
            foreach (var pattern in RestPatterns)
            {
                var match = pattern.Match(url);
                if (match.Success && int.TryParse(match.Groups[1].Value, out var id))
                {
                    var baseUrl = url[..match.Groups[1].Index] + "{ID}";
                    endpoints.Add((baseUrl, id));
                }
            }

            // Also check path segments for numeric IDs
            var uri = new Uri(url, UriKind.RelativeOrAbsolute);
            if (uri.IsAbsoluteUri)
            {
                var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < segments.Length; i++)
                {
                    if (int.TryParse(segments[i], out var id) && id > 0)
                    {
                        var pathParts = uri.AbsolutePath.Split('/');
                        for (int j = 0; j < pathParts.Length; j++)
                        {
                            if (pathParts[j] == segments[i])
                            {
                                pathParts[j] = "{ID}";
                                break;
                            }
                        }
                        var baseUrl = $"{uri.Scheme}://{uri.Authority}{string.Join("/", pathParts)}";
                        endpoints.Add((baseUrl, id));
                    }
                }
            }
        }

        return endpoints.DistinctBy(e => e.Item1).ToList();
    }

    /// <summary>
    /// Discovers endpoints with GUID identifiers from crawled URLs.
    /// </summary>
    private static List<(string BaseUrl, Guid Id)> DiscoverGuidEndpoints(ScanContext context)
    {
        var endpoints = new List<(string, Guid)>();
        var allUrls = new List<string> { context.Target.Url };
        allUrls.AddRange(context.DiscoveredUrls);

        foreach (var url in allUrls.Take(50))
        {
            var match = GuidPattern.Match(url);
            if (match.Success && Guid.TryParse(match.Value, out var guid))
            {
                var baseUrl = url.Replace(match.Value, "{GUID}");
                endpoints.Add((baseUrl, guid));
            }
        }

        return endpoints.DistinctBy(e => e.Item1).ToList();
    }

    // ????????????????????????????????????????????????????????????????????????
    //  1. Numeric ID enumeration
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> TestNumericIdEnumerationAsync(
        ScanContext context, List<(string BaseUrl, int Id)> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var (baseUrl, originalId) in endpoints.Take(8))
        {
            try
            {
                // Fetch the original resource to establish a baseline
                var originalUrl = baseUrl.Replace("{ID}", originalId.ToString());
                var originalResponse = await context.HttpClient.GetAsync(originalUrl);

                if (!originalResponse.IsSuccessStatusCode)
                    continue; // Original resource not accessible — skip

                var originalContent = await originalResponse.Content.ReadAsStringAsync();
                var originalLength = originalContent.Length;

                // Test sequential IDs (increment and decrement)
                var testIds = new[]
                {
                    originalId - 1,
                    originalId - 2,
                    originalId + 1,
                    originalId + 2,
                    1,  // First resource
                    2,
                    100,
                    1000
                }.Where(id => id > 0 && id != originalId).Distinct().Take(6);

                foreach (var testId in testIds)
                {
                    var testUrl = baseUrl.Replace("{ID}", testId.ToString());
                    var testResponse = await context.HttpClient.GetAsync(testUrl);

                    // If we get 200 OK with meaningful content (not an error page)
                    if (testResponse.IsSuccessStatusCode)
                    {
                        var testContent = await testResponse.Content.ReadAsStringAsync();

                        // Heuristic: if the response length is within 20% of the original,
                        // it's likely a legitimate resource (not a 404 HTML page)
                        if (Math.Abs(testContent.Length - originalLength) < originalLength * 0.2 ||
                            testContent.Length > 100)
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "Insecure Direct Object Reference (IDOR) — Numeric ID Enumeration",
                                Description = "The application exposes sequential numeric resource identifiers " +
                                              "without proper authorization checks. An attacker can enumerate " +
                                              "resources by incrementing/decrementing IDs and access data " +
                                              "belonging to other users (horizontal privilege escalation) or " +
                                              "restricted resources (vertical privilege escalation).",
                                Severity = Severity.High,
                                Evidence = $"Original ID: {originalId} (HTTP {(int)originalResponse.StatusCode})\n" +
                                           $"Enumerated ID: {testId} (HTTP {(int)testResponse.StatusCode})\n" +
                                           $"Both resources returned ~{originalLength / 1024}KB of data.\n" +
                                           $"Endpoint pattern: {baseUrl}",
                                Remediation = "Implement object-level authorization checks. Verify that the " +
                                              "authenticated user owns the requested resource before returning it. " +
                                              "Use non-sequential, cryptographically random identifiers (UUIDs). " +
                                              "Implement access control lists (ACLs) or role-based authorization. " +
                                              "Never rely on 'security by obscurity' of ID values.",
                                Url = testUrl,
                                AffectedParameter = "ID path segment",
                                HttpRequest = $"GET {testUrl} HTTP/1.1",
                                HttpResponse = $"HTTP/1.1 {(int)testResponse.StatusCode} OK\n" +
                                               $"Content-Length: {testContent.Length}",
                                ModuleName = Name,
                                OwaspCategory = "A01:2021 - Broken Access Control",
                                CweId = "CWE-639",
                                CvssScore = "8.1",
                                References = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/," +
                                             "https://cwe.mitre.org/data/definitions/639.html," +
                                             "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
                            });

                            // One finding per endpoint is sufficient
                            break;
                        }
                    }
                }
            }
            catch
            {
                // Continue with next endpoint
            }
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  2. GUID enumeration (predictable patterns)
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> TestGuidEnumerationAsync(
        ScanContext context, List<(string BaseUrl, Guid Id)> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var (baseUrl, originalGuid) in endpoints.Take(5))
        {
            try
            {
                var originalUrl = baseUrl.Replace("{GUID}", originalGuid.ToString());
                var originalResponse = await context.HttpClient.GetAsync(originalUrl);

                if (!originalResponse.IsSuccessStatusCode)
                    continue;

                // Check if the GUID is sequential (incremental)
                // Sequential GUIDs have predictable patterns in the last segments
                var guidBytes = originalGuid.ToByteArray();
                
                // Try incrementing the last byte
                var testGuidBytes = (byte[])guidBytes.Clone();
                testGuidBytes[^1]++;
                var testGuid = new Guid(testGuidBytes);

                var testUrl = baseUrl.Replace("{GUID}", testGuid.ToString());
                var testResponse = await context.HttpClient.GetAsync(testUrl);

                if (testResponse.IsSuccessStatusCode)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "IDOR — Sequential GUID Enumeration",
                        Description = "The application uses sequential or predictable GUIDs as resource " +
                                      "identifiers. While GUIDs appear random, these are generated using " +
                                      "sequential algorithms (e.g., SQL Server NEWSEQUENTIALID). An attacker " +
                                      "can predict future/past GUIDs and enumerate resources.",
                        Severity = Severity.High,
                        Evidence = $"Original GUID: {originalGuid}\n" +
                                   $"Predicted GUID: {testGuid}\n" +
                                   $"Both GUIDs returned valid resources (HTTP 200).\n" +
                                   $"Endpoint: {baseUrl}",
                        Remediation = "Use cryptographically random GUIDs (Guid.NewGuid() or UUID v4). " +
                                      "Avoid NEWSEQUENTIALID in SQL Server for user-accessible identifiers. " +
                                      "Implement authorization checks regardless of identifier format. " +
                                      "Consider using opaque tokens instead of database primary keys in URLs.",
                        Url = testUrl,
                        AffectedParameter = "GUID path segment",
                        HttpRequest = $"GET {testUrl} HTTP/1.1",
                        HttpResponse = $"HTTP/1.1 {(int)testResponse.StatusCode} OK",
                        ModuleName = Name,
                        OwaspCategory = "A01:2021 - Broken Access Control",
                        CweId = "CWE-639",
                        CvssScore = "7.5",
                        References = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/," +
                                     "https://cwe.mitre.org/data/definitions/639.html"
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

    // ????????????????????????????????????????????????????????????????????????
    //  3. HTTP verb tampering
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> TestHttpVerbTamperingAsync(
        ScanContext context, List<(string BaseUrl, int Id)> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var (baseUrl, originalId) in endpoints.Take(5))
        {
            var testUrl = baseUrl.Replace("{ID}", originalId.ToString());

            // First, confirm GET works
            var getResponse = await context.HttpClient.GetAsync(testUrl);
            if (!getResponse.IsSuccessStatusCode)
                continue;

            foreach (var method in DangerousMethods)
            {
                try
                {
                    var request = new HttpRequestMessage(method, testUrl);
                    var response = await context.HttpClient.SendAsync(request);

                    // 200 OK, 204 No Content, or 202 Accepted indicate the operation succeeded
                    if (response.IsSuccessStatusCode)
                    {
                        var methodName = method.Method;
                        var impact = methodName switch
                        {
                            "DELETE" => "delete resources",
                            "PUT" => "modify resources",
                            "PATCH" => "partially modify resources",
                            _ => "perform unauthorized operations on resources"
                        };

                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = $"IDOR — HTTP Verb Tampering ({methodName})",
                            Description = $"The endpoint accepts {methodName} requests without proper authorization. " +
                                          $"While GET access is granted, the {methodName} operation should require " +
                                          $"ownership verification. An attacker can {impact} belonging to other users " +
                                          $"by changing the HTTP method.",
                            Severity = methodName == "DELETE" ? Severity.Critical : Severity.High,
                            Evidence = $"Endpoint: {testUrl}\n" +
                                       $"GET request: HTTP {(int)getResponse.StatusCode}\n" +
                                       $"{methodName} request: HTTP {(int)response.StatusCode}\n" +
                                       $"Server accepted the {methodName} operation without authorization.",
                            Remediation = $"Implement authorization checks for all HTTP methods, not just GET. " +
                                          $"Verify ownership before allowing {methodName} operations. Use " +
                                          $"[Authorize] attributes on all action methods in ASP.NET Core. " +
                                          $"Implement middleware that enforces ACL checks regardless of HTTP verb.",
                            Url = testUrl,
                            AffectedParameter = "HTTP Method",
                            HttpRequest = $"{methodName} {testUrl} HTTP/1.1",
                            HttpResponse = $"HTTP/1.1 {(int)response.StatusCode} {response.ReasonPhrase}",
                            ModuleName = Name,
                            OwaspCategory = "A01:2021 - Broken Access Control",
                            CweId = "CWE-352",
                            CvssScore = methodName == "DELETE" ? "9.1" : "8.1",
                            References = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/," +
                                         "https://cwe.mitre.org/data/definitions/352.html"
                        });

                        break; // One verb tampering finding per endpoint
                    }
                }
                catch
                {
                    // Continue
                }
            }
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  4. Query parameter ID manipulation
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> TestQueryParameterIdManipulationAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();
        var allUrls = new List<string> { context.Target.Url };
        allUrls.AddRange(context.DiscoveredUrls);

        // Find URLs with ID-like query parameters
        var urlsWithIdParams = allUrls
            .Where(u => u.Contains('?'))
            .Take(15)
            .ToList();

        foreach (var url in urlsWithIdParams)
        {
            try
            {
                var uri = new Uri(url);
                var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);

                foreach (var paramName in IdParameterNames)
                {
                    var originalValue = queryParams[paramName];
                    if (string.IsNullOrEmpty(originalValue))
                        continue;

                    // Test numeric ID manipulation
                    if (int.TryParse(originalValue, out var originalId))
                    {
                        // Fetch original resource
                        var originalResponse = await context.HttpClient.GetAsync(url);
                        if (!originalResponse.IsSuccessStatusCode)
                            continue;

                        var originalContent = await originalResponse.Content.ReadAsStringAsync();

                        // Try adjacent IDs
                        var testIds = new[] { originalId - 1, originalId + 1, 1 }
                            .Where(id => id > 0 && id != originalId);

                        foreach (var testId in testIds)
                        {
                            var testUrl = url.Replace($"{paramName}={originalId}", $"{paramName}={testId}");
                            var testResponse = await context.HttpClient.GetAsync(testUrl);

                            if (testResponse.IsSuccessStatusCode)
                            {
                                var testContent = await testResponse.Content.ReadAsStringAsync();

                                // Check if we got a different resource (not a duplicate/cache)
                                if (testContent != originalContent && testContent.Length > 100)
                                {
                                    vulnerabilities.Add(new Vulnerability
                                    {
                                        Name = "IDOR — Query Parameter ID Manipulation",
                                        Description = "The application accepts ID values in query parameters without " +
                                                      "proper authorization. An attacker can enumerate resources by " +
                                                      "manipulating the ID parameter and access data belonging to other users.",
                                        Severity = Severity.High,
                                        Evidence = $"Parameter: {paramName}\n" +
                                                   $"Original ID: {originalId}\n" +
                                                   $"Manipulated ID: {testId}\n" +
                                                   $"Both returned different resources (HTTP 200).",
                                        Remediation = "Implement authorization checks for query parameter-based resource " +
                                                      "access. Verify ownership before returning resources. Use session-bound " +
                                                      "identifiers or indirect references instead of exposing database IDs.",
                                        Url = testUrl,
                                        AffectedParameter = paramName,
                                        HttpRequest = $"GET {testUrl} HTTP/1.1",
                                        HttpResponse = $"HTTP/1.1 {(int)testResponse.StatusCode} OK",
                                        ModuleName = Name,
                                        OwaspCategory = "A01:2021 - Broken Access Control",
                                        CweId = "CWE-639",
                                        CvssScore = "7.5",
                                        References = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/," +
                                                     "https://cwe.mitre.org/data/definitions/639.html"
                                    });

                                    goto NextUrl; // One finding per URL
                                }
                            }
                        }
                    }
                }

                NextUrl:;
            }
            catch
            {
                // Continue
            }
        }

        return vulnerabilities;
    }
}
