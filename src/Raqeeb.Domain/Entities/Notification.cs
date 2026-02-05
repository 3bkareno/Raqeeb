using System;

namespace Raqeeb.Domain.Entities
{
    public enum NotificationType
    {
        ScanCompleted,
        ScanFailed,
        CriticalVulnerabilityFound,
        HighSeverityVulnerabilityFound,
        ScheduledScanStarted,
        SystemAlert
    }
    
    public enum NotificationStatus
    {
        Pending,
        Sent,
        Failed
    }

    public class Notification
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Title { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public NotificationType Type { get; set; }
        public NotificationStatus Status { get; set; } = NotificationStatus.Pending;
        
        public string? RecipientEmail { get; set; }
        public string? RecipientUserId { get; set; }
        
        public Guid? RelatedScanJobId { get; set; }
        public ScanJob? RelatedScanJob { get; set; }
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? SentAt { get; set; }
        
        public bool IsRead { get; set; } = false;
        public DateTime? ReadAt { get; set; }
    }
}
