using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Infrastructure.Persistence;

namespace Raqeeb.Infrastructure.Jobs
{
    public class ScanJobProcessor
    {
        private readonly RaqeebDbContext _context;
        private readonly IScanEngine _scanEngine;
        private readonly INotificationService _notificationService;
        private readonly ILogger<ScanJobProcessor> _logger;

        public ScanJobProcessor(
            RaqeebDbContext context,
            IScanEngine scanEngine,
            INotificationService notificationService,
            ILogger<ScanJobProcessor> logger)
        {
            _context = context;
            _scanEngine = scanEngine;
            _notificationService = notificationService;
            _logger = logger;
        }

        public async Task ProcessScanJobAsync(Guid scanJobId)
        {
            _logger.LogInformation("Processing scan job {JobId}", scanJobId);

            var scanJob = await _context.ScanJobs
                .Include(s => s.Target)
                .Include(s => s.ScanProfile)
                .FirstOrDefaultAsync(s => s.Id == scanJobId);

            if (scanJob == null)
            {
                _logger.LogWarning("Scan job {JobId} not found", scanJobId);
                return;
            }

            try
            {
                scanJob.Status = ScanStatus.Running;
                scanJob.StartTime = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                // Execute the scan using the scan engine
                await _scanEngine.StartScanAsync(scanJobId);

                // Reload the scan job to get updated status
                scanJob = await _context.ScanJobs
                    .Include(s => s.Target)
                    .Include(s => s.Vulnerabilities)
                    .FirstOrDefaultAsync(s => s.Id == scanJobId);

                if (scanJob == null) return;

                _logger.LogInformation("Scan job {JobId} completed with {VulnCount} vulnerabilities",
                    scanJobId, scanJob.Vulnerabilities.Count);

                // Send notifications
                await SendScanCompletedNotificationsAsync(scanJob);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scan job {JobId} failed", scanJobId);
                
                scanJob.Status = ScanStatus.Failed;
                scanJob.EndTime = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                // Send failure notification
                await SendScanFailedNotificationAsync(scanJob, ex.Message);
            }
        }

        private async Task SendScanCompletedNotificationsAsync(ScanJob scanJob)
        {
            var target = scanJob.Target;
            var vulnerabilities = await _context.Vulnerabilities
                .Where(v => v.ScanJobId == scanJob.Id)
                .ToListAsync();

            var criticalCount = vulnerabilities.Count(v => v.Severity == Severity.Critical);
            var highCount = vulnerabilities.Count(v => v.Severity == Severity.High);

            // Send completion notification
            if (target?.OwnerId != null)
            {
                var title = $"Scan Completed: {target.Url}";
                var message = $@"
                    <html>
                    <body>
                        <h2>Scan Completed</h2>
                        <p>Your scan of <strong>{target.Url}</strong> has been completed.</p>
                        <h3>Summary:</h3>
                        <ul>
                            <li>Total Vulnerabilities: {vulnerabilities.Count}</li>
                            <li>Critical: {criticalCount}</li>
                            <li>High: {highCount}</li>
                        </ul>
                        <p>Please review the results in your dashboard.</p>
                    </body>
                    </html>";

                await _notificationService.SendNotificationWithPreferencesAsync(
                    target.OwnerId.ToString()!,
                    NotificationType.ScanCompleted,
                    title,
                    message,
                    scanJob.Id);

                // Send critical vulnerability alert if any found
                if (criticalCount > 0)
                {
                    var criticalTitle = $"Critical Vulnerabilities Found: {target.Url}";
                    var criticalMessage = $@"
                        <html>
                        <body>
                            <h2 style='color: red;'>Critical Vulnerabilities Detected</h2>
                            <p><strong>{criticalCount}</strong> critical vulnerabilities were found in your scan of {target.Url}.</p>
                            <p>Immediate action is recommended.</p>
                        </body>
                        </html>";

                    await _notificationService.SendNotificationWithPreferencesAsync(
                        target.OwnerId.ToString()!,
                        NotificationType.CriticalVulnerabilityFound,
                        criticalTitle,
                        criticalMessage,
                        scanJob.Id);
                }
            }
        }

        private async Task SendScanFailedNotificationAsync(ScanJob scanJob, string errorMessage)
        {
            var target = scanJob.Target;
            
            if (target?.OwnerId != null)
            {
                var title = $"Scan Failed: {target.Url}";
                var message = $@"
                    <html>
                    <body>
                        <h2>Scan Failed</h2>
                        <p>Your scan of <strong>{target.Url}</strong> has failed.</p>
                        <p><strong>Error:</strong> {errorMessage}</p>
                        <p>Please check the scan configuration and try again.</p>
                    </body>
                    </html>";

                await _notificationService.SendNotificationWithPreferencesAsync(
                    target.OwnerId.ToString()!,
                    NotificationType.ScanFailed,
                    title,
                    message,
                    scanJob.Id);
            }
        }
    }
}
