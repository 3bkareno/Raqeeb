using System;
using System.Collections.Generic;

namespace Raqeeb.Domain.Entities
{
    public enum ScanStatus
    {
        Queued,
        Running,
        Completed,
        Failed,
        Cancelled
    }

    public class ScanJob
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid TargetId { get; set; }
        public Target? Target { get; set; }
        
        public Guid ScanProfileId { get; set; }
        public ScanProfile? ScanProfile { get; set; }

        public ScanStatus Status { get; set; } = ScanStatus.Queued;
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
        
        public ICollection<Vulnerability> Vulnerabilities { get; set; } = new List<Vulnerability>();
    }
}
