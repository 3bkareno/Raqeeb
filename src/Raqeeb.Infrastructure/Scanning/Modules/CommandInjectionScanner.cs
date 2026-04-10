using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules;

/// <summary>
/// Detects OS Command Injection vulnerabilities by injecting shell metacharacters
/// and measuring response-time differentials (time-based) as well as inspecting
/// response bodies for command-output signatures (error-based / output-based).
/// Covers Unix/Linux and Windows command interpreters.
/// </summary>
public class CommandInjectionScanner : IScannerModule
{
    public string Name => "CommandInjectionScanner";
    public string Description => "Detects OS Command Injection via time-based delay, error-based output, and blind detection techniques.";

    // ?? Delay in seconds injected into time-based payloads ??????????????????
    private const int InjectedDelaySec = 5;
    private const long DelayThresholdMs = 4000;   // 80 % of injected delay

    // ?? Parameters commonly piped to back-end shell commands ????????????????
    private static readonly string[] InjectableParameters =
    [
        "cmd", "exec", "command", "execute", "ping", "query", "jump",
        "code", "reg", "do", "func", "arg", "option", "load", "process",
        "step", "read", "feature", "exe", "module", "payload", "run",
        "print", "ip", "host", "hostname", "domain", "interface",
        "port", "filename", "file", "path", "dir", "log", "daemon",
        "upload", "download", "email", "to", "from", "name", "id"
    ];

    // ?? Time-based payloads (Unix + Windows) ????????????????????????????????
    // The idea: if the server concatenates user input into a shell command,
    // these payloads force a measurable delay.
    private static readonly string[] TimeBasedPayloadsUnix =
    [
        $"; sleep {InjectedDelaySec}",
        $"| sleep {InjectedDelaySec}",
        $"|| sleep {InjectedDelaySec}",
        $"& sleep {InjectedDelaySec}",
        $"&& sleep {InjectedDelaySec}",
        $"`sleep {InjectedDelaySec}`",
        $"$(sleep {InjectedDelaySec})",
        $"; sleep {InjectedDelaySec} #",
        $"| sleep {InjectedDelaySec} #",
        $"%0a sleep {InjectedDelaySec}",
        $"; /bin/sleep {InjectedDelaySec}",
        $"{{{{sleep,{InjectedDelaySec}}}}}",            // brace expansion bash
        $"; ping -c {InjectedDelaySec} 127.0.0.1",
    ];

    private static readonly string[] TimeBasedPayloadsWindows =
    [
        $"& timeout /t {InjectedDelaySec} /nobreak",
        $"| timeout /t {InjectedDelaySec} /nobreak",
        $"&& timeout /t {InjectedDelaySec} /nobreak",
        $"|| timeout /t {InjectedDelaySec} /nobreak",
        $"& ping -n {InjectedDelaySec + 1} 127.0.0.1",
        $"| ping -n {InjectedDelaySec + 1} 127.0.0.1",
        $"&& ping -n {InjectedDelaySec + 1} 127.0.0.1",
    ];

    // ?? Error / output-based payloads (looking for known output) ????????????
    private static readonly (string Payload, string[] Signatures)[] OutputPayloadsUnix =
    [
        ("; id",                  ["uid=", "gid=", "groups="]),
        ("| id",                  ["uid=", "gid=", "groups="]),
        ("`id`",                  ["uid=", "gid=", "groups="]),
        ("$(id)",                 ["uid=", "gid=", "groups="]),
        ("; whoami",              []),   // whoami output is unpredictable, check below
        ("| whoami",              []),
        ("; uname -a",           ["Linux", "Darwin", "Unix"]),
        ("| uname -a",           ["Linux", "Darwin", "Unix"]),
        ("; cat /etc/passwd",    ["root:", "/bin/bash", "/bin/sh"]),
        ("| cat /etc/passwd",    ["root:", "/bin/bash", "/bin/sh"]),
        ("`cat /etc/passwd`",    ["root:", "/bin/bash", "/bin/sh"]),
        ("$(cat /etc/passwd)",   ["root:", "/bin/bash", "/bin/sh"]),
        ("; echo RAQEEB_CMD_INJECT_CANARY", ["RAQEEB_CMD_INJECT_CANARY"]),
        ("| echo RAQEEB_CMD_INJECT_CANARY", ["RAQEEB_CMD_INJECT_CANARY"]),
        ("`echo RAQEEB_CMD_INJECT_CANARY`", ["RAQEEB_CMD_INJECT_CANARY"]),
        ("$(echo RAQEEB_CMD_INJECT_CANARY)", ["RAQEEB_CMD_INJECT_CANARY"]),
    ];

    private static readonly (string Payload, string[] Signatures)[] OutputPayloadsWindows =
    [
        ("& whoami",             []),
        ("| whoami",             []),
        ("& echo RAQEEB_CMD_INJECT_CANARY", ["RAQEEB_CMD_INJECT_CANARY"]),
        ("| echo RAQEEB_CMD_INJECT_CANARY", ["RAQEEB_CMD_INJECT_CANARY"]),
        ("& type C:\\Windows\\win.ini", ["[fonts]", "[extensions]"]),
        ("| type C:\\Windows\\win.ini", ["[fonts]", "[extensions]"]),
        ("& ipconfig",           ["Windows IP Configuration", "IPv4", "Subnet Mask"]),
        ("| ipconfig",           ["Windows IP Configuration", "IPv4", "Subnet Mask"]),
        ("& ver",                ["Microsoft Windows"]),
        ("| ver",                ["Microsoft Windows"]),
        ("& set",                ["COMPUTERNAME=", "OS=", "SystemRoot="]),
    ];

    // ?? Error string patterns that indicate shell errors leaking ????????????
    private static readonly string[] ShellErrorPatterns =
    [
        "sh:",
        "bash:",
        "/bin/sh:",
        "/bin/bash:",
        "syntax error",
        "not found",
        "command not found",
        "is not recognized as an internal or external command",
        "not recognized as the name of a cmdlet",
        "cannot execute binary file",
        "permission denied",
        "no such file or directory",
        "'cmd' is not recognized",
        "the system cannot find the path specified",
    ];

    // ????????????????????????????????????????????????????????????????????????
    //  Entry point
    // ????????????????????????????????????????????????????????????????????????

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // 1. Time-based detection — most reliable, low false-positive rate
            var timeVulns = await DetectTimeBasedInjectionAsync(context);
            vulnerabilities.AddRange(timeVulns);

            // 2. Output / error-based detection — catches verbose apps
            var outputVulns = await DetectOutputBasedInjectionAsync(context);
            vulnerabilities.AddRange(outputVulns);

            // 3. Blind shell-error detection — shell error strings in response
            var blindVulns = await DetectBlindShellErrorsAsync(context);
            vulnerabilities.AddRange(blindVulns);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"CommandInjection Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  1. Time-based detection
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> DetectTimeBasedInjectionAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();
        var testedParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allUrls = BuildTargetUrls(context);

        foreach (var baseUrl in allUrls.Take(5))
        {
            foreach (var param in InjectableParameters.Take(12))
            {
                if (testedParams.Contains(param)) continue;

                // ?? Unix payloads ???????????????????????????????????????
                foreach (var payload in TimeBasedPayloadsUnix.Take(5))
                {
                    if (await MeasureDelayAsync(context, baseUrl, param, payload) is { } vuln)
                    {
                        vuln.Name = "OS Command Injection (Time-Based — Unix)";
                        vulnerabilities.Add(vuln);
                        testedParams.Add(param);
                        break;
                    }
                }

                if (testedParams.Contains(param)) continue;

                // ?? Windows payloads ????????????????????????????????????
                foreach (var payload in TimeBasedPayloadsWindows.Take(4))
                {
                    if (await MeasureDelayAsync(context, baseUrl, param, payload) is { } vuln)
                    {
                        vuln.Name = "OS Command Injection (Time-Based — Windows)";
                        vulnerabilities.Add(vuln);
                        testedParams.Add(param);
                        break;
                    }
                }
            }
        }

        return vulnerabilities;
    }

    private async Task<Vulnerability?> MeasureDelayAsync(
        ScanContext context, string baseUrl, string param, string payload)
    {
        try
        {
            // Establish a baseline response time first
            var baselineSw = Stopwatch.StartNew();
            var separator = baseUrl.Contains('?') ? "&" : "?";
            await context.HttpClient.GetAsync($"{baseUrl}{separator}{param}=testvalue");
            baselineSw.Stop();
            var baselineMs = baselineSw.ElapsedMilliseconds;

            // Now inject the delay payload
            var sw = Stopwatch.StartNew();
            var testUrl = $"{baseUrl}{separator}{param}={HttpUtility.UrlEncode(payload)}";
            var response = await context.HttpClient.GetAsync(testUrl);
            sw.Stop();

            var injectedMs = sw.ElapsedMilliseconds;

            // The response must be noticeably slower than the baseline AND exceed
            // the absolute threshold. This two-gate approach cuts false positives
            // on inherently slow servers.
            if (injectedMs > DelayThresholdMs && injectedMs > baselineMs + 3000)
            {
                var rawRequest = $"GET {testUrl} HTTP/1.1";
                var statusCode = (int)response.StatusCode;

                return new Vulnerability
                {
                    Description = $"The application appears to execute OS commands with user-controllable input. " +
                                  $"A time-based payload caused a {injectedMs}ms delay (baseline {baselineMs}ms). " +
                                  $"An attacker can leverage this for full Remote Code Execution (RCE).",
                    Severity = Severity.Critical,
                    Evidence = $"Parameter: {param}\nPayload: {payload}\n" +
                               $"Baseline response time: {baselineMs}ms\n" +
                               $"Injected response time: {injectedMs}ms\n" +
                               $"HTTP Status: {statusCode}",
                    Remediation = "Never pass user input directly to OS command functions (exec, system, popen, " +
                                  "Process.Start, Runtime.exec). Use language-level APIs instead (e.g., " +
                                  "System.Net.NetworkInformation.Ping). If shell execution is unavoidable, use " +
                                  "strict allowlists, escape all metacharacters, and run with least-privilege.",
                    Url = testUrl,
                    AffectedParameter = param,
                    HttpRequest = rawRequest,
                    HttpResponse = $"HTTP/1.1 {statusCode}\nResponse time: {injectedMs}ms",
                    ModuleName = Name,
                    OwaspCategory = "A03:2021 - Injection",
                    CweId = "CWE-78",
                    CvssScore = "9.8",
                    References = "https://owasp.org/Top10/A03_2021-Injection/," +
                                 "https://cwe.mitre.org/data/definitions/78.html," +
                                 "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                };
            }
        }
        catch
        {
            // Network error or timeout — continue with next payload
        }

        return null;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  2. Output / error-based detection
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> DetectOutputBasedInjectionAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();
        var testedParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allUrls = BuildTargetUrls(context);

        foreach (var baseUrl in allUrls.Take(5))
        {
            // Grab a baseline response to compare content against
            string baselineContent;
            try
            {
                var baseResp = await context.HttpClient.GetAsync(baseUrl);
                baselineContent = await baseResp.Content.ReadAsStringAsync();
            }
            catch
            {
                continue;
            }

            foreach (var param in InjectableParameters.Take(12))
            {
                if (testedParams.Contains(param)) continue;

                // ?? Unix ????????????????????????????????????????????????
                foreach (var (payload, signatures) in OutputPayloadsUnix.Take(8))
                {
                    if (await TryOutputPayloadAsync(context, baseUrl, param, payload,
                            signatures, baselineContent, "Unix") is { } vuln)
                    {
                        vulnerabilities.Add(vuln);
                        testedParams.Add(param);
                        break;
                    }
                }

                if (testedParams.Contains(param)) continue;

                // ?? Windows ?????????????????????????????????????????????
                foreach (var (payload, signatures) in OutputPayloadsWindows.Take(6))
                {
                    if (await TryOutputPayloadAsync(context, baseUrl, param, payload,
                            signatures, baselineContent, "Windows") is { } vuln)
                    {
                        vulnerabilities.Add(vuln);
                        testedParams.Add(param);
                        break;
                    }
                }
            }
        }

        return vulnerabilities;
    }

    private async Task<Vulnerability?> TryOutputPayloadAsync(
        ScanContext context, string baseUrl, string param,
        string payload, string[] signatures, string baselineContent, string os)
    {
        try
        {
            var separator = baseUrl.Contains('?') ? "&" : "?";
            var testUrl = $"{baseUrl}{separator}{param}={HttpUtility.UrlEncode(payload)}";

            var response = await context.HttpClient.GetAsync(testUrl);
            var content = await response.Content.ReadAsStringAsync();

            // For canary payloads the match is straightforward
            bool matched = false;
            string matchedSignature = string.Empty;

            if (signatures.Length > 0)
            {
                foreach (var sig in signatures)
                {
                    // The signature must appear in the injected response but NOT in the baseline
                    if (content.Contains(sig, StringComparison.OrdinalIgnoreCase) &&
                        !baselineContent.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        matched = true;
                        matchedSignature = sig;
                        break;
                    }
                }
            }

            if (!matched) return null;

            var rawRequest = $"GET {testUrl} HTTP/1.1";
            var evidenceSnippet = ExtractEvidenceSnippet(content, matchedSignature, maxLength: 300);

            return new Vulnerability
            {
                Name = $"OS Command Injection (Output-Based — {os})",
                Description = $"The application executes OS commands with user-controllable input and reflects " +
                              $"the output in the HTTP response. Detected {os} command output signature " +
                              $"'{matchedSignature}' in the response body.",
                Severity = Severity.Critical,
                Evidence = $"Parameter: {param}\nPayload: {payload}\n" +
                           $"Matched signature: {matchedSignature}\n" +
                           $"Response snippet:\n{evidenceSnippet}",
                Remediation = "Never pass user input directly to OS command functions. Use language-level " +
                              "APIs. If shell execution is unavoidable, use strict allowlists, escape all " +
                              "metacharacters, and run with least-privilege.",
                Url = testUrl,
                AffectedParameter = param,
                HttpRequest = rawRequest,
                HttpResponse = $"HTTP/1.1 {(int)response.StatusCode}\n{evidenceSnippet}",
                ModuleName = Name,
                OwaspCategory = "A03:2021 - Injection",
                CweId = "CWE-78",
                CvssScore = "9.8",
                References = "https://owasp.org/Top10/A03_2021-Injection/," +
                             "https://cwe.mitre.org/data/definitions/78.html," +
                             "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
            };
        }
        catch
        {
            return null;
        }
    }

    // ????????????????????????????????????????????????????????????????????????
    //  3. Blind shell-error detection
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<Vulnerability>> DetectBlindShellErrorsAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();
        var allUrls = BuildTargetUrls(context);

        // Payloads that should break shell syntax and cause an error message
        string[] syntaxBreakers =
        [
            "; :; :",              // no-op chain — errors on non-shell apps
            "| |",
            "& &",
            "|| |",
            "&& &",
            "$()",
            "``",
            "%0a",
            "\n",
            ";\x00",
        ];

        foreach (var baseUrl in allUrls.Take(3))
        {
            // Get baseline content
            string baselineContent;
            try
            {
                var baseResp = await context.HttpClient.GetAsync(baseUrl);
                baselineContent = await baseResp.Content.ReadAsStringAsync();
            }
            catch
            {
                continue;
            }

            foreach (var param in InjectableParameters.Take(8))
            {
                foreach (var breaker in syntaxBreakers.Take(5))
                {
                    try
                    {
                        var separator = baseUrl.Contains('?') ? "&" : "?";
                        var testUrl = $"{baseUrl}{separator}{param}={HttpUtility.UrlEncode(breaker)}";

                        var response = await context.HttpClient.GetAsync(testUrl);
                        var content = await response.Content.ReadAsStringAsync();

                        // Look for shell error messages that were NOT in the baseline
                        foreach (var pattern in ShellErrorPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase) &&
                                !baselineContent.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Name = "Possible OS Command Injection (Shell Error Leaked)",
                                    Description = "The application appears to pass user input to a shell " +
                                                  "command interpreter. A syntax-breaking payload caused " +
                                                  "a shell error message to leak in the response. While " +
                                                  "this alone may not prove exploitation, it strongly " +
                                                  "indicates the presence of a command injection sink.",
                                    Severity = Severity.High,
                                    Evidence = $"Parameter: {param}\nPayload: {breaker}\n" +
                                               $"Shell error pattern: {pattern}\n" +
                                               $"Response snippet:\n{ExtractEvidenceSnippet(content, pattern, 200)}",
                                    Remediation = "Audit the server-side code for command execution " +
                                                  "functions (exec, system, popen, Process.Start, " +
                                                  "Runtime.exec). Replace with safe APIs.",
                                    Url = testUrl,
                                    AffectedParameter = param,
                                    HttpRequest = $"GET {testUrl} HTTP/1.1",
                                    HttpResponse = $"HTTP/1.1 {(int)response.StatusCode}\n" +
                                                   $"{ExtractEvidenceSnippet(content, pattern, 200)}",
                                    ModuleName = Name,
                                    OwaspCategory = "A03:2021 - Injection",
                                    CweId = "CWE-78",
                                    CvssScore = "7.5",
                                    References = "https://owasp.org/Top10/A03_2021-Injection/," +
                                                 "https://cwe.mitre.org/data/definitions/78.html"
                                });

                                // One finding per parameter is enough for this technique
                                goto NextParam;
                            }
                        }
                    }
                    catch
                    {
                        // Continue
                    }
                }
                NextParam:;
            }
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Helpers
    // ????????????????????????????????????????????????????????????????????????

    /// <summary>
    /// Builds a list of target URLs from the base target URL and any
    /// discovered URLs that contain query-string parameters.
    /// </summary>
    private static List<string> BuildTargetUrls(ScanContext context)
    {
        var urls = new List<string> { context.Target.Url };

        // Include discovered URLs that already carry query parameters —
        // these are more likely to hit injectable back-end code.
        foreach (var url in context.DiscoveredUrls)
        {
            if (url.Contains('?'))
            {
                urls.Add(url);
            }
        }

        return urls;
    }

    /// <summary>
    /// Extracts a short snippet of the response body surrounding the first
    /// occurrence of <paramref name="marker"/> for use as evidence.
    /// </summary>
    private static string ExtractEvidenceSnippet(string content, string marker, int maxLength)
    {
        if (string.IsNullOrEmpty(marker) || string.IsNullOrEmpty(content))
            return content.Length > maxLength ? content[..maxLength] + "…" : content;

        var idx = content.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return content.Length > maxLength ? content[..maxLength] + "…" : content;

        var start = Math.Max(0, idx - 60);
        var end = Math.Min(content.Length, idx + marker.Length + 60);
        var snippet = content[start..end];

        return snippet.Length > maxLength ? snippet[..maxLength] + "…" : snippet;
    }
}
