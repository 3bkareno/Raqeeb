using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning
{
    public class ScanEngine : IScanEngine
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IEnumerable<IScannerModule> _modules;
        private readonly ILogger<ScanEngine> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IHttpCrawler _crawler;

        public ScanEngine(
            IServiceScopeFactory scopeFactory,
            IEnumerable<IScannerModule> modules,
            ILogger<ScanEngine> logger,
            IHttpClientFactory httpClientFactory,
            IHttpCrawler crawler)
        {
            _scopeFactory = scopeFactory;
            _modules = modules;
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _crawler = crawler;
        }

        public Task CancelScanAsync(Guid scanJobId)
        {
            // Implementation for cancellation (e.g., CancellationTokenSource map)
            return Task.CompletedTask;
        }

        public Task StartScanAsync(Guid scanJobId)
        {
            // Run in background
            _ = Task.Run(async () => await ExecuteScan(scanJobId));
            return Task.CompletedTask;
        }

        private async Task ExecuteScan(Guid scanJobId)
        {
            using var scope = _scopeFactory.CreateScope();
            var jobRepo = scope.ServiceProvider.GetRequiredService<IRepository<ScanJob>>();
            var vulnRepo = scope.ServiceProvider.GetRequiredService<IRepository<Vulnerability>>();
            var targetRepo = scope.ServiceProvider.GetRequiredService<IRepository<Target>>();
            var profileRepo = scope.ServiceProvider.GetRequiredService<IRepository<ScanProfile>>();

            try
            {
                var job = await jobRepo.GetByIdAsync(scanJobId);
                if (job == null)
                {
                    _logger.LogError("ScanJob {ScanJobId} not found", scanJobId);
                    return;
                }

                job.Status = ScanStatus.Running;
                await jobRepo.UpdateAsync(job);

                var target = await targetRepo.GetByIdAsync(job.TargetId);
                if (target == null) throw new Exception("Target not found");

                // In real app, load profile and filter modules
                // var profile = await profileRepo.GetByIdAsync(job.ScanProfileId);

                var httpClient = _httpClientFactory.CreateClient();
                var context = new ScanContext(target, new ScanProfile(), httpClient);

                _logger.LogInformation("Crawling {Url}...", target.Url);
                var discoveredUrls = await _crawler.CrawlAsync(target.Url);
                context.DiscoveredUrls.AddRange(discoveredUrls);
                _logger.LogInformation("Discovered {Count} URLs", context.DiscoveredUrls.Count);

                foreach (var module in _modules)
                {
                    _logger.LogInformation("Running module {ModuleName} for {Url}", module.Name, target.Url);
                    var vulns = await module.ScanAsync(context);
                    foreach (var v in vulns)
                    {
                        v.ScanJobId = job.Id;
                        v.ModuleName ??= module.Name;
                        EnrichComplianceFields(v);
                        await vulnRepo.AddAsync(v);
                    }
                }

                // Reload the job to avoid concurrency issues before final update
                job = await jobRepo.GetByIdAsync(scanJobId);
                if (job != null)
                {
                    job.Status = ScanStatus.Completed;
                    job.EndTime = DateTime.UtcNow;
                    await jobRepo.UpdateAsync(job);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scan failed for job {ScanJobId}", scanJobId);
                
                try
                {
                    // Reload the job before updating to avoid concurrency issues
                    var job = await jobRepo.GetByIdAsync(scanJobId);
                    if (job != null)
                    {
                        job.Status = ScanStatus.Failed;
                        job.EndTime = DateTime.UtcNow;
                        await jobRepo.UpdateAsync(job);
                    }
                }
                catch (Exception updateEx)
                {
                    _logger.LogError(updateEx, "Failed to update job status to Failed for job {ScanJobId}", scanJobId);
                }
            }
        }

        /// <summary>
        /// Fills in OWASP/CWE/CVSS fields when a scanner module did not set them,
        /// based on common vulnerability name patterns.
        /// </summary>
        private static void EnrichComplianceFields(Vulnerability v)
        {
            // Only fill fields that the module left empty
            if (!string.IsNullOrEmpty(v.OwaspCategory) &&
                !string.IsNullOrEmpty(v.CweId) &&
                !string.IsNullOrEmpty(v.CvssScore))
            {
                return;
            }

            var name = v.Name.ToLowerInvariant();

            var (owasp, cwe, cvss) = name switch
            {
                _ when name.Contains("xss") || name.Contains("cross-site scripting")
                    => ("A03:2021 - Injection", "CWE-79", v.Severity >= Severity.High ? "8.1" : "6.1"),

                _ when name.Contains("sql injection")
                    => ("A03:2021 - Injection", "CWE-89", v.Severity >= Severity.High ? "9.8" : "7.5"),

                _ when name.Contains("ssrf") || name.Contains("server-side request")
                    => ("A10:2021 - Server-Side Request Forgery", "CWE-918", "9.1"),

                _ when name.Contains("cors")
                    => ("A05:2021 - Security Misconfiguration", "CWE-942", "5.3"),

                _ when name.Contains("clickjack") || name.Contains("frame")
                    => ("A05:2021 - Security Misconfiguration", "CWE-1021", "4.7"),

                _ when name.Contains("csrf") || name.Contains("cross-site request forgery")
                    => ("A01:2021 - Broken Access Control", "CWE-352", "6.5"),

                _ when name.Contains("redirect")
                    => ("A01:2021 - Broken Access Control", "CWE-601", "5.4"),

                _ when name.Contains("certificate") || name.Contains("ssl") || name.Contains("tls") || name.Contains("https")
                    => ("A02:2021 - Cryptographic Failures", "CWE-295", "5.3"),

                _ when name.Contains("hsts")
                    => ("A05:2021 - Security Misconfiguration", "CWE-319", "5.3"),

                _ when name.Contains("path traversal") || name.Contains("local file")
                    => ("A01:2021 - Broken Access Control", "CWE-22", "9.1"),

                _ when name.Contains("directory") || name.Contains("hidden path")
                    => ("A05:2021 - Security Misconfiguration", "CWE-538", "5.3"),

                _ when name.Contains("port") && name.Contains("open")
                    => ("A05:2021 - Security Misconfiguration", "CWE-200", v.Severity >= Severity.High ? "7.5" : "3.7"),

                _ when name.Contains("subdomain")
                    => ("A05:2021 - Security Misconfiguration", "CWE-200", "3.7"),

                _ when name.Contains("cookie")
                    => ("A05:2021 - Security Misconfiguration", "CWE-614", "5.3"),

                _ when name.Contains("session")
                    => ("A07:2021 - Identification and Authentication Failures", "CWE-384", "5.3"),

                _ when name.Contains("disclosure") || name.Contains("information") || name.Contains("exposed")
                    => ("A05:2021 - Security Misconfiguration", "CWE-200", "5.3"),

                _ when name.Contains("method") || name.Contains("trace") || name.Contains("verb")
                    => ("A05:2021 - Security Misconfiguration", "CWE-749", "5.3"),

                _ => ("A05:2021 - Security Misconfiguration", "CWE-16", "3.7")
            };

            v.OwaspCategory ??= owasp;
            v.CweId ??= cwe;
            v.CvssScore ??= cvss;
        }
    }
}
