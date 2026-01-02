using System.Collections.Generic;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Domain.Interfaces
{
    public interface IScannerModule
    {
        string Name { get; }
        string Description { get; }
        
        Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context);
    }
}
