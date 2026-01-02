using System;
using System.Collections.Generic;

namespace Raqeeb.Domain.Entities
{
    public class Target
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Url { get; set; } = string.Empty;
        public string OwnerId { get; set; } = string.Empty; // For multi-tenancy/RBAC
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public bool IsVerified { get; set; }
        
        // Navigation properties
        public ICollection<ScanJob> ScanJobs { get; set; } = new List<ScanJob>();
    }
}
