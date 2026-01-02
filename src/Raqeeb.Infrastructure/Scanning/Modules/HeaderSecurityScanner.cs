using System.Collections.Generic;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules
{
    public class HeaderSecurityScanner : IScannerModule
    {
        public string Name => "HeaderSecurityScanner";
        public string Description => "Checks for missing security headers.";

        public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            try
            {
                var response = await context.HttpClient.GetAsync(context.Target.Url);
                
                if (!response.Headers.Contains("X-Content-Type-Options"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing X-Content-Type-Options",
                        Description = "The X-Content-Type-Options header is missing.",
                        Severity = Severity.Low,
                        Remediation = "Add 'X-Content-Type-Options: nosniff' header.",
                        Url = context.Target.Url
                    });
                }

                if (!response.Headers.Contains("Strict-Transport-Security"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Name = "Missing HSTS",
                        Description = "HTTP Strict Transport Security (HSTS) header is missing.",
                        Severity = Severity.Medium,
                        Remediation = "Add 'Strict-Transport-Security' header.",
                        Url = context.Target.Url
                    });
                }
            }
            catch
            {
                // Log error or report connectivity issue
            }

            return vulnerabilities;
        }
    }
}
