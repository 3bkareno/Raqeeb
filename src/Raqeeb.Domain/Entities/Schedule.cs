using System;

namespace Raqeeb.Domain.Entities
{
    public class Schedule
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        
        public Guid TargetId { get; set; }
        public Target? Target { get; set; }
        
        public Guid ScanProfileId { get; set; }
        public ScanProfile? ScanProfile { get; set; }
        
        /// <summary>
        /// CRON expression for scheduling (e.g., "0 0 * * *" for daily at midnight)
        /// </summary>
        public string CronExpression { get; set; } = string.Empty;
        
        public bool IsEnabled { get; set; } = true;
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastRunAt { get; set; }
        public DateTime? NextRunAt { get; set; }
        
        public string? CreatedBy { get; set; }
    }
}
