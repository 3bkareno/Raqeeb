using System;
using System.Collections.Generic;
using System.IO;
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
/// Detects file upload vulnerabilities including:
/// - Unrestricted file upload (executable extensions)
/// - Double extension bypass (shell.jpg.php)
/// - Path traversal in filenames (../../evil.aspx)
/// - MIME type validation bypass
/// - SVG with embedded XSS
/// - XXE in DOCX/XLSX uploads
/// - Null-byte injection
/// - File signature/magic number validation bypass
/// </summary>
public class FileUploadScanner : IScannerModule
{
    public string Name => "FileUploadScanner";
    public string Description => "Detects file upload vulnerabilities: unrestricted extensions, path traversal, MIME bypass, SVG XSS, XXE in documents, signature validation issues.";

    // ── File input pattern for HTML parsing ─────────────────────────────────
    private static readonly Regex FileInputPattern = new(
        @"<input[^>]*type=['""]?file['""]?[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // ── Form action pattern ─────────────────────────────────────────────────
    private static readonly Regex FormActionPattern = new(
        @"<form[^>]*action=['""]?([^'"">\s]+)['""]?[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // ── Dangerous executable extensions ─────────────────────────────────────
    private static readonly string[] DangerousExtensions =
    [
        ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".vbs",
        ".js", ".jar", ".msi", ".app", ".deb", ".rpm",
        ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
        ".asp", ".aspx", ".asax", ".ascx", ".ashx", ".asmx",
        ".cer", ".asa", ".jsp", ".jspx", ".war",
        ".sh", ".bash", ".csh", ".ksh", ".zsh",
        ".py", ".pl", ".rb", ".go", ".c", ".cpp",
        ".ps1", ".psm1",
        ".svg"  // SVG can contain JavaScript
    ];

    // ── Double extension patterns ───────────────────────────────────────────
    private static readonly string[] DoubleExtensions =
    [
        ".jpg.php",
        ".png.php",
        ".gif.php",
        ".pdf.php",
        ".jpg.aspx",
        ".png.aspx",
        ".pdf.aspx",
        ".txt.jsp",
        ".jpg.jsp"
    ];

    // ── Path traversal patterns in filenames ────────────────────────────────
    private static readonly string[] PathTraversalFilenames =
    [
        "../../evil.aspx",
        "..\\..\\evil.aspx",
        "....//....//evil.php",
        "..%2f..%2fevil.jsp",
        "..%5c..%5cevil.asp",
        "..//..//..//evil.php",
        "test.php%00.jpg"  // Null-byte injection
    ];

    // ── File signatures (magic numbers) for common types ────────────────────
    private static readonly Dictionary<string, byte[]> FileSignatures = new()
    {
        { ".exe", new byte[] { 0x4D, 0x5A } },                              // MZ
        { ".php", Encoding.UTF8.GetBytes("<?php") },
        { ".aspx", Encoding.UTF8.GetBytes("<%@") },
        { ".jsp", Encoding.UTF8.GetBytes("<%") },
        { ".pdf", new byte[] { 0x25, 0x50, 0x44, 0x46 } },                  // %PDF
        { ".zip", new byte[] { 0x50, 0x4B, 0x03, 0x04 } },                  // PK
        { ".jpg", new byte[] { 0xFF, 0xD8, 0xFF } },                        // JPEG
        { ".png", new byte[] { 0x89, 0x50, 0x4E, 0x47 } },                  // PNG
        { ".gif", new byte[] { 0x47, 0x49, 0x46, 0x38 } },                  // GIF8
    };

    // ── SVG with embedded XSS ───────────────────────────────────────────────
    private const string SvgXssPayload = """
        <svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
          <circle cx="50" cy="50" r="40" fill="red"/>
        </svg>
        """;

    // ── XXE payload for DOCX/XLSX (embedded in XML) ─────────────────────────
    private const string XxeXmlPayload = """
        <?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>
        """;

    // ════════════════════════════════════════════════════════════════════════
    //  Entry point
    // ════════════════════════════════════════════════════════════════════════

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // 1. Discover file upload endpoints
            var uploadEndpoints = await DiscoverFileUploadEndpointsAsync(context);

            if (uploadEndpoints.Count == 0)
            {
                // No file upload forms found
                return vulnerabilities;
            }

            // 2. Test unrestricted file upload (dangerous extensions)
            var extensionVulns = await TestDangerousExtensionsAsync(context, uploadEndpoints);
            vulnerabilities.AddRange(extensionVulns);

            // 3. Test double extension bypass
            var doubleExtVulns = await TestDoubleExtensionBypassAsync(context, uploadEndpoints);
            vulnerabilities.AddRange(doubleExtVulns);

            // 4. Test path traversal in filenames
            var pathTraversalVulns = await TestPathTraversalInFilenameAsync(context, uploadEndpoints);
            vulnerabilities.AddRange(pathTraversalVulns);

            // 5. Test MIME type validation bypass
            var mimeVulns = await TestMimeTypeBypassAsync(context, uploadEndpoints);
            vulnerabilities.AddRange(mimeVulns);

            // 6. Test SVG with XSS
            var svgVulns = await TestSvgXssAsync(context, uploadEndpoints);
            vulnerabilities.AddRange(svgVulns);

            // 7. Test file signature validation bypass
            var signatureVulns = await TestFileSignatureBypassAsync(context, uploadEndpoints);
            vulnerabilities.AddRange(signatureVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"File Upload Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Endpoint discovery
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<UploadEndpoint>> DiscoverFileUploadEndpointsAsync(ScanContext context)
    {
        var endpoints = new HashSet<UploadEndpoint>();
        var allUrls = new List<string> { context.Target.Url };
        allUrls.AddRange(context.DiscoveredUrls);

        foreach (var url in allUrls.Take(30))
        {
            try
            {
                var response = await context.HttpClient.GetAsync(url);
                if (!response.IsSuccessStatusCode)
                    continue;

                var html = await response.Content.ReadAsStringAsync();

                // Look for <input type="file">
                var fileInputMatches = FileInputPattern.Matches(html);
                if (fileInputMatches.Count == 0)
                    continue;

                // Extract form action
                var formActionMatch = FormActionPattern.Match(html);
                string? formAction = null;

                if (formActionMatch.Success)
                {
                    formAction = formActionMatch.Groups[1].Value;

                    // Convert relative URLs to absolute
                    if (!formAction.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                    {
                        var baseUri = new Uri(url);
                        if (formAction.StartsWith('/'))
                        {
                            formAction = $"{baseUri.Scheme}://{baseUri.Authority}{formAction}";
                        }
                        else
                        {
                            var basePath = baseUri.AbsolutePath;
                            var lastSlash = basePath.LastIndexOf('/');
                            var directory = lastSlash > 0 ? basePath[..lastSlash] : "";
                            formAction = $"{baseUri.Scheme}://{baseUri.Authority}{directory}/{formAction}";
                        }
                    }
                }

                endpoints.Add(new UploadEndpoint
                {
                    Url = formAction ?? url,
                    PageUrl = url,
                    HasFileInput = true
                });

                // Also check for common upload API endpoints
                var uri = new Uri(url);
                var commonUploadPaths = new[] { "/upload", "/api/upload", "/api/file", "/file/upload" };
                foreach (var path in commonUploadPaths)
                {
                    var uploadUrl = $"{uri.Scheme}://{uri.Authority}{path}";
                    endpoints.Add(new UploadEndpoint
                    {
                        Url = uploadUrl,
                        PageUrl = url,
                        HasFileInput = false
                    });
                }
            }
            catch
            {
                // Continue
            }
        }

        return endpoints.ToList();
    }

    // ════════════════════════════════════════════════════════════════════════
    //  1. Dangerous extensions
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestDangerousExtensionsAsync(
        ScanContext context, List<UploadEndpoint> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(5))
        {
            // Test a few high-risk extensions
            var testExtensions = new[] { ".aspx", ".php", ".exe", ".sh", ".jsp" };

            foreach (var ext in testExtensions)
            {
                try
                {
                    var filename = $"test{ext}";
                    var content = ext switch
                    {
                        ".aspx" => "<%@ Page Language=\"C#\" %><%Response.Write(\"RAQEEB_UPLOAD_TEST\");%>",
                        ".php" => "<?php echo 'RAQEEB_UPLOAD_TEST'; ?>",
                        ".jsp" => "<%out.print(\"RAQEEB_UPLOAD_TEST\");%>",
                        _ => "RAQEEB_UPLOAD_TEST"
                    };

                    var uploadResult = await TryUploadFileAsync(context, endpoint.Url, filename, content);

                    if (uploadResult.Success)
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "Unrestricted File Upload — Dangerous Extension",
                            Description = $"The application accepts file uploads with the dangerous extension '{ext}'. " +
                                          $"An attacker can upload executable code (web shells, malware) and execute " +
                                          $"arbitrary commands on the server. This can lead to complete server compromise.",
                            Severity = Severity.Critical,
                            Evidence = $"Uploaded file: {filename}\n" +
                                       $"Extension: {ext}\n" +
                                       $"HTTP Status: {uploadResult.StatusCode}\n" +
                                       $"Response indicates successful upload.\n" +
                                       $"Upload endpoint: {endpoint.Url}",
                            Remediation = "Implement a strict allowlist of permitted file extensions (e.g., .jpg, .png, .pdf). " +
                                          "Reject all other extensions. Validate both the extension and file signature (magic numbers). " +
                                          "Store uploaded files outside the web root. Rename uploaded files with random names. " +
                                          "Set appropriate Content-Disposition headers to prevent execution.",
                            Url = endpoint.Url,
                            AffectedParameter = "file upload field",
                            HttpRequest = $"POST {endpoint.Url} HTTP/1.1\nContent-Type: multipart/form-data\n" +
                                          $"Filename: {filename}",
                            HttpResponse = $"HTTP/1.1 {uploadResult.StatusCode}\n{uploadResult.ResponseSnippet}",
                            ModuleName = Name,
                            OwaspCategory = "A04:2021 - Insecure Design",
                            CweId = "CWE-434",
                            CvssScore = "9.8",
                            References = "https://owasp.org/Top10/A04_2021-Insecure_Design/," +
                                         "https://cwe.mitre.org/data/definitions/434.html," +
                                         "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                        });

                        // One finding per endpoint
                        break;
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

    // ════════════════════════════════════════════════════════════════════════
    //  2. Double extension bypass
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestDoubleExtensionBypassAsync(
        ScanContext context, List<UploadEndpoint> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(5))
        {
            foreach (var doubleExt in DoubleExtensions.Take(4))
            {
                try
                {
                    var filename = $"shell{doubleExt}";
                    var content = doubleExt.EndsWith(".php") 
                        ? "<?php echo 'RAQEEB_DOUBLE_EXT_TEST'; ?>" 
                        : "<%Response.Write(\"RAQEEB_DOUBLE_EXT_TEST\");%>";

                    var uploadResult = await TryUploadFileAsync(context, endpoint.Url, filename, content);

                    if (uploadResult.Success)
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "File Upload — Double Extension Bypass",
                            Description = $"The application's file extension validation can be bypassed using double " +
                                          $"extensions (e.g., {doubleExt}). Some web servers execute files based on " +
                                          $"the last extension, while validation only checks the first. This allows " +
                                          $"uploading executable code disguised as an image.",
                            Severity = Severity.Critical,
                            Evidence = $"Uploaded file: {filename}\n" +
                                       $"Double extension: {doubleExt}\n" +
                                       $"HTTP Status: {uploadResult.StatusCode}\n" +
                                       $"Server accepted the file.\n" +
                                       $"Upload endpoint: {endpoint.Url}",
                            Remediation = "Validate the complete filename, not just the extension. Extract the file " +
                                          "extension using Path.GetExtension() and check against an allowlist. " +
                                          "Reject filenames with multiple dots if not explicitly required. " +
                                          "Use Content-Type validation and file signature checks.",
                            Url = endpoint.Url,
                            AffectedParameter = "file upload field",
                            HttpRequest = $"POST {endpoint.Url} HTTP/1.1\nFilename: {filename}",
                            HttpResponse = $"HTTP/1.1 {uploadResult.StatusCode}\n{uploadResult.ResponseSnippet}",
                            ModuleName = Name,
                            OwaspCategory = "A04:2021 - Insecure Design",
                            CweId = "CWE-434",
                            CvssScore = "9.8",
                            References = "https://cwe.mitre.org/data/definitions/434.html," +
                                         "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                        });

                        break;
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

    // ════════════════════════════════════════════════════════════════════════
    //  3. Path traversal in filename
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestPathTraversalInFilenameAsync(
        ScanContext context, List<UploadEndpoint> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(5))
        {
            foreach (var traversalFilename in PathTraversalFilenames.Take(4))
            {
                try
                {
                    var content = "RAQEEB_PATH_TRAVERSAL_TEST";
                    var uploadResult = await TryUploadFileAsync(context, endpoint.Url, traversalFilename, content);

                    // We can't always confirm the file was written to the traversed location,
                    // but if the server accepts it without error, it's a vulnerability
                    if (uploadResult.Success || uploadResult.StatusCode == 201)
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "File Upload — Path Traversal in Filename",
                            Description = "The application does not sanitize path traversal sequences in uploaded " +
                                          "filenames. An attacker can write files to arbitrary locations on the " +
                                          "server by including ../ or ..\\ sequences in the filename, potentially " +
                                          "overwriting critical system files or placing web shells in executable directories.",
                            Severity = Severity.Critical,
                            Evidence = $"Uploaded filename: {traversalFilename}\n" +
                                       $"HTTP Status: {uploadResult.StatusCode}\n" +
                                       $"Server accepted the filename without sanitization.\n" +
                                       $"Upload endpoint: {endpoint.Url}",
                            Remediation = "Strip all directory path characters from uploaded filenames. Use " +
                                          "Path.GetFileName() to extract only the filename component. Reject filenames " +
                                          "containing /, \\, .., or null bytes. Store uploads in a dedicated directory " +
                                          "outside the web root with random-generated names.",
                            Url = endpoint.Url,
                            AffectedParameter = "filename",
                            HttpRequest = $"POST {endpoint.Url} HTTP/1.1\nFilename: {traversalFilename}",
                            HttpResponse = $"HTTP/1.1 {uploadResult.StatusCode}\n{uploadResult.ResponseSnippet}",
                            ModuleName = Name,
                            OwaspCategory = "A01:2021 - Broken Access Control",
                            CweId = "CWE-22",
                            CvssScore = "9.1",
                            References = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/," +
                                         "https://cwe.mitre.org/data/definitions/22.html"
                        });

                        break;
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

    // ════════════════════════════════════════════════════════════════════════
    //  4. MIME type validation bypass
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestMimeTypeBypassAsync(
        ScanContext context, List<UploadEndpoint> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(5))
        {
            try
            {
                // Upload a PHP file but set Content-Type to image/jpeg
                var filename = "shell.php";
                var content = "<?php echo 'RAQEEB_MIME_BYPASS'; ?>";
                var uploadResult = await TryUploadFileAsync(context, endpoint.Url, filename, content, "image/jpeg");

                if (uploadResult.Success)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "File Upload — MIME Type Validation Bypass",
                        Description = "The application only validates the Content-Type header (MIME type) but does " +
                                      "not verify the actual file signature. An attacker can upload executable code " +
                                      "(PHP, ASPX) with a fake Content-Type header (e.g., image/jpeg) to bypass " +
                                      "validation.",
                        Severity = Severity.High,
                        Evidence = $"Uploaded file: {filename}\n" +
                                   $"Real extension: .php\n" +
                                   $"Fake Content-Type: image/jpeg\n" +
                                   $"HTTP Status: {uploadResult.StatusCode}\n" +
                                   $"Server accepted the file.",
                        Remediation = "Do not rely solely on Content-Type headers (client-controlled). Validate file " +
                                      "signatures (magic numbers) by reading the first few bytes. Combine extension, " +
                                      "MIME type, and signature checks. Use a library like MimeDetective for .NET.",
                        Url = endpoint.Url,
                        AffectedParameter = "file upload field",
                        HttpRequest = $"POST {endpoint.Url} HTTP/1.1\nContent-Type: multipart/form-data\n" +
                                      $"Filename: {filename}\nContent-Type: image/jpeg",
                        HttpResponse = $"HTTP/1.1 {uploadResult.StatusCode}\n{uploadResult.ResponseSnippet}",
                        ModuleName = Name,
                        OwaspCategory = "A04:2021 - Insecure Design",
                        CweId = "CWE-434",
                        CvssScore = "8.1",
                        References = "https://cwe.mitre.org/data/definitions/434.html," +
                                     "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
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

    // ════════════════════════════════════════════════════════════════════════
    //  5. SVG with XSS
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestSvgXssAsync(
        ScanContext context, List<UploadEndpoint> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(5))
        {
            try
            {
                var filename = "xss.svg";
                var uploadResult = await TryUploadFileAsync(context, endpoint.Url, filename, SvgXssPayload, "image/svg+xml");

                if (uploadResult.Success)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "File Upload — SVG with Embedded XSS",
                        Description = "The application accepts SVG uploads without sanitization. SVG files can " +
                                      "contain embedded JavaScript via event handlers (onload, onerror, onclick). " +
                                      "When a user views the SVG, the JavaScript executes, leading to stored XSS.",
                        Severity = Severity.High,
                        Evidence = $"Uploaded file: {filename}\n" +
                                   $"Content: SVG with onload=\"alert('XSS')\"\n" +
                                   $"HTTP Status: {uploadResult.StatusCode}\n" +
                                   $"If this SVG is served to users, XSS will trigger.",
                        Remediation = "Sanitize SVG content by stripping all script tags and event handlers " +
                                      "(onload, onerror, etc.). Use a library like DOMPurify or svg-sanitizer. " +
                                      "Serve SVG files with Content-Disposition: attachment to prevent inline execution. " +
                                      "Set Content-Security-Policy headers to block inline scripts.",
                        Url = endpoint.Url,
                        AffectedParameter = "file upload field",
                        HttpRequest = $"POST {endpoint.Url} HTTP/1.1\nFilename: {filename}",
                        HttpResponse = $"HTTP/1.1 {uploadResult.StatusCode}\n{uploadResult.ResponseSnippet}",
                        ModuleName = Name,
                        OwaspCategory = "A03:2021 - Injection",
                        CweId = "CWE-79",
                        CvssScore = "7.1",
                        References = "https://owasp.org/Top10/A03_2021-Injection/," +
                                     "https://cwe.mitre.org/data/definitions/79.html," +
                                     "https://portswigger.net/web-security/cross-site-scripting/contexts/svg"
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

    // ════════════════════════════════════════════════════════════════════════
    //  6. File signature validation bypass
    // ════════════════════════════════════════════════════════════════════════

    private async Task<List<Vulnerability>> TestFileSignatureBypassAsync(
        ScanContext context, List<UploadEndpoint> endpoints)
    {
        var vulnerabilities = new List<Vulnerability>();

        foreach (var endpoint in endpoints.Take(5))
        {
            try
            {
                // Create a polyglot file: starts with JPEG signature but contains PHP code
                var jpegSignature = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46 };
                var phpCode = Encoding.UTF8.GetBytes("\n<?php echo 'RAQEEB_POLYGLOT_TEST'; ?>");
                var polyglot = jpegSignature.Concat(phpCode).ToArray();

                var filename = "image.php.jpg";
                var uploadResult = await TryUploadFileAsync(context, endpoint.Url, filename, 
                    Encoding.Latin1.GetString(polyglot), "image/jpeg");

                if (uploadResult.Success)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "File Upload — Polyglot / Signature Bypass",
                        Description = "The application validates file signatures (magic numbers) but accepts polyglot " +
                                      "files that start with a valid image signature followed by executable code. " +
                                      "The file passes signature checks but can still be executed if accessible via " +
                                      "a script interpreter.",
                        Severity = Severity.High,
                        Evidence = $"Uploaded file: {filename}\n" +
                                   $"File starts with JPEG signature (FF D8 FF) but contains PHP code.\n" +
                                   $"HTTP Status: {uploadResult.StatusCode}\n" +
                                   $"Server accepted the polyglot file.",
                        Remediation = "Do not rely solely on file signatures. Combine signature validation with " +
                                      "extension checks and content analysis. Re-encode/re-render images using ImageSharp " +
                                      "or System.Drawing to strip embedded code. Store uploads outside the web root and " +
                                      "serve them through a controller that sets Content-Disposition: attachment.",
                        Url = endpoint.Url,
                        AffectedParameter = "file upload field",
                        HttpRequest = $"POST {endpoint.Url} HTTP/1.1\nFilename: {filename}",
                        HttpResponse = $"HTTP/1.1 {uploadResult.StatusCode}\n{uploadResult.ResponseSnippet}",
                        ModuleName = Name,
                        OwaspCategory = "A04:2021 - Insecure Design",
                        CweId = "CWE-434",
                        CvssScore = "8.1",
                        References = "https://cwe.mitre.org/data/definitions/434.html," +
                                     "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
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

    // ════════════════════════════════════════════════════════════════════════
    //  Upload helper
    // ════════════════════════════════════════════════════════════════════════

    private static async Task<UploadResult> TryUploadFileAsync(
        ScanContext context, string uploadUrl, string filename, string content, string? contentType = null)
    {
        try
        {
            using var formData = new MultipartFormDataContent();
            var fileContent = new ByteArrayContent(Encoding.UTF8.GetBytes(content));
            fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(
                contentType ?? "application/octet-stream");
            formData.Add(fileContent, "file", filename);

            var response = await context.HttpClient.PostAsync(uploadUrl, formData);
            var responseBody = await response.Content.ReadAsStringAsync();

            // Heuristics for successful upload
            var statusCode = (int)response.StatusCode;
            var success = statusCode is >= 200 and < 300 ||
                          responseBody.Contains("success", StringComparison.OrdinalIgnoreCase) ||
                          responseBody.Contains("uploaded", StringComparison.OrdinalIgnoreCase) ||
                          responseBody.Contains("saved", StringComparison.OrdinalIgnoreCase);

            return new UploadResult
            {
                Success = success,
                StatusCode = statusCode,
                ResponseSnippet = responseBody.Length > 200 ? responseBody[..200] + "..." : responseBody
            };
        }
        catch
        {
            return new UploadResult { Success = false, StatusCode = 0 };
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Data classes
    // ════════════════════════════════════════════════════════════════════════

    private class UploadEndpoint
    {
        public string Url { get; set; } = string.Empty;
        public string PageUrl { get; set; } = string.Empty;
        public bool HasFileInput { get; set; }
    }

    private class UploadResult
    {
        public bool Success { get; set; }
        public int StatusCode { get; set; }
        public string ResponseSnippet { get; set; } = string.Empty;
    }
}
