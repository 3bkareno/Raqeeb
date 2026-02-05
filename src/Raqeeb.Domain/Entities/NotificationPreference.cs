using System;

namespace Raqeeb.Domain.Entities
{
    public class NotificationPreference
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid UserId { get; set; }
        public ApplicationUser? User { get; set; }
        
        // Email Notification Settings
        public bool EmailOnScanComplete { get; set; } = true;
        public bool EmailOnScanFailed { get; set; } = true;
        public bool EmailOnCriticalVulnerability { get; set; } = true;
        public bool EmailOnHighSeverityVulnerability { get; set; } = false;
        
        // In-App Notification Settings
        public bool InAppNotifications { get; set; } = true;
        
        // Webhook Settings
        public bool WebhookEnabled { get; set; } = false;
        public string? WebhookUrl { get; set; }
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
    }
}
