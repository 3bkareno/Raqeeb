using System.Collections.Generic;
using System.Threading.Tasks;

namespace Raqeeb.Domain.Interfaces
{
    public interface IHttpCrawler
    {
        Task<IEnumerable<string>> CrawlAsync(string rootUrl, int maxDepth = 2);
    }
}
