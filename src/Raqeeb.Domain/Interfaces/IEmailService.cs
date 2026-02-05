using System.Threading.Tasks;

namespace Raqeeb.Domain.Interfaces
{
    public interface IEmailService
    {
        /// <summary>
        /// Sends an email message
        /// </summary>
        Task SendEmailAsync(string to, string subject, string body, bool isHtml = true);
        
        /// <summary>
        /// Sends an email message to multiple recipients
        /// </summary>
        Task SendEmailAsync(string[] to, string subject, string body, bool isHtml = true);
        
        /// <summary>
        /// Sends an email using a template
        /// </summary>
        Task SendTemplateEmailAsync(string to, string templateName, object model);
    }
}
