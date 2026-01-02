using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Infrastructure.Scanning
{
    public class HttpCrawler : IHttpCrawler
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<HttpCrawler> _logger;

        public HttpCrawler(IHttpClientFactory httpClientFactory, ILogger<HttpCrawler> logger)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
        }

        public async Task<IEnumerable<string>> CrawlAsync(string rootUrl, int maxDepth = 2)
        {
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var toVisit = new Queue<(string Url, int Depth)>();
            
            // Normalize root URL
            if (!rootUrl.EndsWith("/")) rootUrl += "/";
            
            toVisit.Enqueue((rootUrl, 0));
            visited.Add(rootUrl);

            var client = _httpClientFactory.CreateClient();
            var discoveredUrls = new List<string> { rootUrl };

            while (toVisit.Count > 0)
            {
                var (currentUrl, depth) = toVisit.Dequeue();
                if (depth >= maxDepth) continue;

                try
                {
                    // Basic check to avoid downloading non-HTML content
                    // In a real crawler, we'd use HEAD request first
                    var html = await client.GetStringAsync(currentUrl);
                    var links = ExtractLinks(html, rootUrl);

                    foreach (var link in links)
                    {
                        if (!visited.Contains(link))
                        {
                            visited.Add(link);
                            discoveredUrls.Add(link);
                            toVisit.Enqueue((link, depth + 1));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to crawl {Url}", currentUrl);
                }
            }

            return discoveredUrls;
        }

        private IEnumerable<string> ExtractLinks(string html, string rootUrl)
        {
            var regex = new Regex("href\\s*=\\s*[\"']([^\"']*)[\"']", RegexOptions.IgnoreCase);
            var matches = regex.Matches(html);
            
            if (!Uri.TryCreate(rootUrl, UriKind.Absolute, out var rootUri))
            {
                yield break;
            }

            foreach (Match match in matches)
            {
                var href = match.Groups[1].Value;
                if (string.IsNullOrWhiteSpace(href) || href.StartsWith("#") || href.StartsWith("javascript:")) continue;

                if (Uri.TryCreate(rootUri, href, out var result))
                {
                    // Only follow links on the same host
                    if (result.Host.Equals(rootUri.Host, StringComparison.OrdinalIgnoreCase) && 
                        (result.Scheme == Uri.UriSchemeHttp || result.Scheme == Uri.UriSchemeHttps))
                    {
                        yield return result.ToString();
                    }
                }
            }
        }
    }
}
