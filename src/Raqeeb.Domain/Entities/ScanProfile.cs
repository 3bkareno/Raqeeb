using System;
using System.Collections.Generic;

namespace Raqeeb.Domain.Entities
{
    public class ScanProfile
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        
        // List of module keys/names to enable
        public List<string> EnabledModules { get; set; } = new List<string>();
        
        public int RequestTimeoutSeconds { get; set; } = 30;
        public int MaxConcurrency { get; set; } = 5;
    }
}
