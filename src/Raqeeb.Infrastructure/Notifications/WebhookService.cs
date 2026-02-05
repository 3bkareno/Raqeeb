using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Infrastructure.Notifications
{
    public class WebhookService : IWebhookService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<WebhookService> _logger;

        public WebhookService(IHttpClientFactory httpClientFactory, ILogger<WebhookService> logger)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
        }

        public async Task SendWebhookAsync(string url, object payload)
        {
            try
            {
                var client = _httpClientFactory.CreateClient();
                var json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                _logger.LogInformation("Sending webhook to {Url}", url);
                
                var response = await client.PostAsync(url, content);
                
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Webhook sent successfully to {Url}", url);
                }
                else
                {
                    _logger.LogWarning("Webhook failed with status code {StatusCode} for {Url}", 
                        response.StatusCode, url);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send webhook to {Url}", url);
                throw;
            }
        }
    }
}
