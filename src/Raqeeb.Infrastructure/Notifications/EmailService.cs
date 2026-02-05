using System;
using System.Threading.Tasks;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MimeKit;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Infrastructure.Notifications
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendEmailAsync(string to, string subject, string body, bool isHtml = true)
        {
            await SendEmailAsync(new[] { to }, subject, body, isHtml);
        }

        public async Task SendEmailAsync(string[] to, string subject, string body, bool isHtml = true)
        {
            try
            {
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(
                    _configuration["Email:FromName"] ?? "Raqeeb Security Scanner",
                    _configuration["Email:FromAddress"] ?? "noreply@raqeeb.io"
                ));

                foreach (var recipient in to)
                {
                    message.To.Add(MailboxAddress.Parse(recipient));
                }

                message.Subject = subject;

                var builder = new BodyBuilder();
                if (isHtml)
                {
                    builder.HtmlBody = body;
                }
                else
                {
                    builder.TextBody = body;
                }

                message.Body = builder.ToMessageBody();

                using var client = new SmtpClient();
                
                var host = _configuration["Email:SmtpHost"];
                var port = int.Parse(_configuration["Email:SmtpPort"] ?? "587");
                var useSsl = bool.Parse(_configuration["Email:UseSsl"] ?? "true");
                var username = _configuration["Email:Username"];
                var password = _configuration["Email:Password"];

                if (string.IsNullOrEmpty(host))
                {
                    _logger.LogWarning("Email SMTP host not configured. Email not sent.");
                    return;
                }

                await client.ConnectAsync(host, port, useSsl ? SecureSocketOptions.StartTls : SecureSocketOptions.None);

                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    await client.AuthenticateAsync(username, password);
                }

                await client.SendAsync(message);
                await client.DisconnectAsync(true);

                _logger.LogInformation("Email sent successfully to {Recipients}", string.Join(", ", to));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Recipients}", string.Join(", ", to));
                throw;
            }
        }

        public async Task SendTemplateEmailAsync(string to, string templateName, object model)
        {
            // For now, we'll use simple string templates
            // In the future, this can be enhanced with Razor templates or similar
            var (subject, body) = GenerateEmailFromTemplate(templateName, model);
            await SendEmailAsync(to, subject, body, true);
        }

        private (string subject, string body) GenerateEmailFromTemplate(string templateName, object model)
        {
            // Simple template generation - can be enhanced later
            return templateName switch
            {
                "ScanCompleted" => ("Scan Completed", $"<html><body><h2>Scan Completed</h2><p>Your scan has been completed successfully.</p></body></html>"),
                "ScanFailed" => ("Scan Failed", $"<html><body><h2>Scan Failed</h2><p>Your scan has failed. Please check the logs for more details.</p></body></html>"),
                "CriticalVulnerability" => ("Critical Vulnerability Found", $"<html><body><h2>Critical Vulnerability Detected</h2><p>A critical vulnerability has been found in your scan.</p></body></html>"),
                _ => ("Notification", $"<html><body><p>You have a new notification from Raqeeb.</p></body></html>")
            };
        }
    }
}
