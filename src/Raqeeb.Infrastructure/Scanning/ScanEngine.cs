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
            var targetRepo = scope.ServiceProvider.GetRequiredService<IRepository<Target>>();
            var profileRepo = scope.ServiceProvider.GetRequiredService<IRepository<ScanProfile>>();

            ScanJob? job = null;

            try
            {
                job = await jobRepo.GetByIdAsync(scanJobId);
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
                        job.Vulnerabilities.Add(v);
                    }
                }

                job.Status = ScanStatus.Completed;
                job.EndTime = DateTime.UtcNow;
                await jobRepo.UpdateAsync(job);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scan failed for job {ScanJobId}", scanJobId);
                if (job != null)
                {
                    try
                    {
                        job.Status = ScanStatus.Failed;
                        job.EndTime = DateTime.UtcNow;
                        await jobRepo.UpdateAsync(job);
                    }
                    catch (Exception updateEx)
                    {
                        _logger.LogError(updateEx, "Failed to update job status to Failed for job {ScanJobId}", scanJobId);
                    }
                }
            }
        }
    }
}
