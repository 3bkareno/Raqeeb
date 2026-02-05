using System;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;

namespace Raqeeb.Domain.Interfaces
{
    public interface INotificationService
    {
        /// <summary>
        /// Creates and sends a notification
        /// </summary>
        Task SendNotificationAsync(NotificationType type, string title, string message, 
            string? recipientEmail = null, string? recipientUserId = null, Guid? relatedScanJobId = null);
        
        /// <summary>
        /// Sends notification based on user preferences
        /// </summary>
        Task SendNotificationWithPreferencesAsync(string userId, NotificationType type, 
            string title, string message, Guid? relatedScanJobId = null);
        
        /// <summary>
        /// Marks a notification as read
        /// </summary>
        Task MarkAsReadAsync(Guid notificationId);
        
        /// <summary>
        /// Gets unread notification count for a user
        /// </summary>
        Task<int> GetUnreadCountAsync(string userId);
    }
}
