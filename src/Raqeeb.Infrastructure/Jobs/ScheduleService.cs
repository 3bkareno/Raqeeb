using System;
using System.Threading.Tasks;
using Hangfire;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Infrastructure.Persistence;

namespace Raqeeb.Infrastructure.Jobs
{
    public class ScheduleService : IScheduleService
    {
        private readonly RaqeebDbContext _context;
        private readonly ILogger<ScheduleService> _logger;

        public ScheduleService(RaqeebDbContext context, ILogger<ScheduleService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task CreateRecurringJobAsync(Schedule schedule)
        {
            if (!schedule.IsEnabled)
            {
                _logger.LogInformation("Schedule {ScheduleId} is disabled, skipping job creation", schedule.Id);
                return;
            }

            var jobId = $"schedule_{schedule.Id}";
            
            RecurringJob.AddOrUpdate(
                jobId,
                () => ExecuteScheduledScanAsync(schedule.Id),
                schedule.CronExpression,
                new RecurringJobOptions
                {
                    TimeZone = TimeZoneInfo.Utc
                });

            schedule.NextRunAt = GetNextRunTime(schedule.CronExpression);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Recurring job created for schedule {ScheduleId} with CRON {Cron}", 
                schedule.Id, schedule.CronExpression);
        }

        public async Task UpdateRecurringJobAsync(Schedule schedule)
        {
            var jobId = $"schedule_{schedule.Id}";
            
            if (schedule.IsEnabled)
            {
                RecurringJob.AddOrUpdate(
                    jobId,
                    () => ExecuteScheduledScanAsync(schedule.Id),
                    schedule.CronExpression,
                    new RecurringJobOptions
                    {
                        TimeZone = TimeZoneInfo.Utc
                    });

                schedule.NextRunAt = GetNextRunTime(schedule.CronExpression);
                _logger.LogInformation("Recurring job updated for schedule {ScheduleId}", schedule.Id);
            }
            else
            {
                RecurringJob.RemoveIfExists(jobId);
                schedule.NextRunAt = null;
                _logger.LogInformation("Recurring job removed for disabled schedule {ScheduleId}", schedule.Id);
            }

            await _context.SaveChangesAsync();
        }

        public async Task RemoveRecurringJobAsync(Guid scheduleId)
        {
            var jobId = $"schedule_{scheduleId}";
            RecurringJob.RemoveIfExists(jobId);
            _logger.LogInformation("Recurring job removed for schedule {ScheduleId}", scheduleId);
            await Task.CompletedTask;
        }

        public async Task TriggerScheduledScanAsync(Guid scheduleId)
        {
            BackgroundJob.Enqueue(() => ExecuteScheduledScanAsync(scheduleId));
            _logger.LogInformation("Manually triggered scan for schedule {ScheduleId}", scheduleId);
            await Task.CompletedTask;
        }

        public async Task ExecuteScheduledScanAsync(Guid scheduleId)
        {
            _logger.LogInformation("Executing scheduled scan for schedule {ScheduleId}", scheduleId);

            var schedule = await _context.Schedules
                .Include(s => s.Target)
                .Include(s => s.ScanProfile)
                .FirstOrDefaultAsync(s => s.Id == scheduleId);

            if (schedule == null)
            {
                _logger.LogWarning("Schedule {ScheduleId} not found", scheduleId);
                return;
            }

            if (!schedule.IsEnabled)
            {
                _logger.LogInformation("Schedule {ScheduleId} is disabled, skipping execution", scheduleId);
                return;
            }

            // Create a new scan job
            var scanJob = new ScanJob
            {
                TargetId = schedule.TargetId,
                ScanProfileId = schedule.ScanProfileId,
                Status = ScanStatus.Queued,
                StartTime = DateTime.UtcNow
            };

            _context.ScanJobs.Add(scanJob);
            schedule.LastRunAt = DateTime.UtcNow;
            schedule.NextRunAt = GetNextRunTime(schedule.CronExpression);
            
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created scan job {JobId} for schedule {ScheduleId}", 
                scanJob.Id, scheduleId);

            // Enqueue the scan job to be processed
            BackgroundJob.Enqueue<ScanJobProcessor>(x => x.ProcessScanJobAsync(scanJob.Id));
        }

        private DateTime? GetNextRunTime(string cronExpression)
        {
            try
            {
                // This is a simplified implementation
                // In production, you'd use Cronos or similar library to calculate next run
                // For now, return a placeholder
                return DateTime.UtcNow.AddHours(1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to calculate next run time for CRON expression {Cron}", cronExpression);
                return null;
            }
        }
    }
}
