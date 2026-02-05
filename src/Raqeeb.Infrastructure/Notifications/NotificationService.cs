using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Infrastructure.Persistence;

namespace Raqeeb.Infrastructure.Notifications
{
    public class NotificationService : INotificationService
    {
        private readonly RaqeebDbContext _context;
        private readonly IEmailService _emailService;
        private readonly IWebhookService _webhookService;
        private readonly ILogger<NotificationService> _logger;

        public NotificationService(
            RaqeebDbContext context,
            IEmailService emailService,
            IWebhookService webhookService,
            ILogger<NotificationService> logger)
        {
            _context = context;
            _emailService = emailService;
            _webhookService = webhookService;
            _logger = logger;
        }

        public async Task SendNotificationAsync(
            NotificationType type,
            string title,
            string message,
            string? recipientEmail = null,
            string? recipientUserId = null,
            Guid? relatedScanJobId = null)
        {
            var notification = new Notification
            {
                Type = type,
                Title = title,
                Message = message,
                RecipientEmail = recipientEmail,
                RecipientUserId = recipientUserId,
                RelatedScanJobId = relatedScanJobId
            };

            _context.Notifications.Add(notification);
            await _context.SaveChangesAsync();

            // Send email if recipient email is provided
            if (!string.IsNullOrEmpty(recipientEmail))
            {
                try
                {
                    await _emailService.SendEmailAsync(recipientEmail, title, message, true);
                    notification.Status = NotificationStatus.Sent;
                    notification.SentAt = DateTime.UtcNow;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send email notification to {Email}", recipientEmail);
                    notification.Status = NotificationStatus.Failed;
                }

                await _context.SaveChangesAsync();
            }
        }

        public async Task SendNotificationWithPreferencesAsync(
            string userId,
            NotificationType type,
            string title,
            string message,
            Guid? relatedScanJobId = null)
        {
            var userGuid = Guid.Parse(userId);
            var preferences = await _context.NotificationPreferences
                .FirstOrDefaultAsync(p => p.UserId == userGuid);

            var user = await _context.Users.FindAsync(userGuid);
            
            if (user == null)
            {
                _logger.LogWarning("User {UserId} not found for notification", userId);
                return;
            }

            // Default preferences if not set
            var emailEnabled = preferences?.EmailOnScanComplete ?? true;
            var webhookEnabled = preferences?.WebhookEnabled ?? false;
            var webhookUrl = preferences?.WebhookUrl;

            // Check specific notification type preferences
            bool shouldSendEmail = type switch
            {
                NotificationType.ScanCompleted => preferences?.EmailOnScanComplete ?? true,
                NotificationType.ScanFailed => preferences?.EmailOnScanFailed ?? true,
                NotificationType.CriticalVulnerabilityFound => preferences?.EmailOnCriticalVulnerability ?? true,
                NotificationType.HighSeverityVulnerabilityFound => preferences?.EmailOnHighSeverityVulnerability ?? false,
                _ => true
            };

            string? recipientEmail = shouldSendEmail ? user.Email : null;

            await SendNotificationAsync(type, title, message, recipientEmail, userId, relatedScanJobId);

            // Send webhook if enabled
            if (webhookEnabled && !string.IsNullOrEmpty(webhookUrl))
            {
                try
                {
                    await _webhookService.SendWebhookAsync(webhookUrl, new
                    {
                        type = type.ToString(),
                        title,
                        message,
                        userId,
                        scanJobId = relatedScanJobId,
                        timestamp = DateTime.UtcNow
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send webhook notification to {Url}", webhookUrl);
                }
            }
        }

        public async Task MarkAsReadAsync(Guid notificationId)
        {
            var notification = await _context.Notifications.FindAsync(notificationId);
            if (notification != null)
            {
                notification.IsRead = true;
                notification.ReadAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();
            }
        }

        public async Task<int> GetUnreadCountAsync(string userId)
        {
            return await _context.Notifications
                .Where(n => n.RecipientUserId == userId && !n.IsRead)
                .CountAsync();
        }
    }
}
