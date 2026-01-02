using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Scans.Queries
{
    public class ScanStatusDto
    {
        public Guid Id { get; set; }
        public string Status { get; set; } = string.Empty;
        public int VulnerabilityCount { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }
    }

    public class GetScanStatusQuery : IRequest<ScanStatusDto?>
    {
        public Guid ScanJobId { get; set; }
    }

    public class GetScanStatusQueryHandler : IRequestHandler<GetScanStatusQuery, ScanStatusDto?>
    {
        private readonly IRepository<ScanJob> _scanJobRepository;

        public GetScanStatusQueryHandler(IRepository<ScanJob> scanJobRepository)
        {
            _scanJobRepository = scanJobRepository;
        }

        public async Task<ScanStatusDto?> Handle(GetScanStatusQuery request, CancellationToken cancellationToken)
        {
            var job = await _scanJobRepository.GetByIdAsync(request.ScanJobId);
            if (job == null) return null;

            return new ScanStatusDto
            {
                Id = job.Id,
                Status = job.Status.ToString(),
                VulnerabilityCount = job.Vulnerabilities.Count,
                StartTime = job.StartTime,
                EndTime = job.EndTime
            };
        }
    }
}
