using System;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;

namespace Raqeeb.Domain.Interfaces
{
    public interface IScanEngine
    {
        Task StartScanAsync(Guid scanJobId);
        Task CancelScanAsync(Guid scanJobId);
    }
}
