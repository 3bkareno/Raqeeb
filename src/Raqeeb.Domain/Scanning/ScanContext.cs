using System;
using System.Collections.Generic;
using System.Net.Http;
using Raqeeb.Domain.Entities;

namespace Raqeeb.Domain.Scanning
{
    public class ScanContext
    {
        public Target Target { get; }
        public ScanProfile Profile { get; }
        public HttpClient HttpClient { get; } // Or a wrapper IHttpClient
        
        // Shared state for the scan (e.g., crawled URLs)
        public List<string> DiscoveredUrls { get; } = new List<string>();
        
        public ScanContext(Target target, ScanProfile profile, HttpClient httpClient)
        {
            Target = target;
            Profile = profile;
            HttpClient = httpClient;
        }
    }
}
