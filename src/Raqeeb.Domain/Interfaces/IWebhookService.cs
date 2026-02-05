using System.Threading.Tasks;

namespace Raqeeb.Domain.Interfaces
{
    public interface IWebhookService
    {
        /// <summary>
        /// Sends a webhook notification to a URL
        /// </summary>
        Task SendWebhookAsync(string url, object payload);
    }
}
