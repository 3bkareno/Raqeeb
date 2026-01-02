using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Scans.Commands
{
    public class CreateScanCommand : IRequest<Guid>
    {
        public string Url { get; set; } = string.Empty;
        public Guid ProfileId { get; set; }
        public string OwnerId { get; set; } = string.Empty;
    }

    public class CreateScanCommandHandler : IRequestHandler<CreateScanCommand, Guid>
    {
        private readonly IRepository<Target> _targetRepository;
        private readonly IRepository<ScanJob> _scanJobRepository;
        private readonly IScanEngine _scanEngine;

        public CreateScanCommandHandler(
            IRepository<Target> targetRepository,
            IRepository<ScanJob> scanJobRepository,
            IScanEngine scanEngine)
        {
            _targetRepository = targetRepository;
            _scanJobRepository = scanJobRepository;
            _scanEngine = scanEngine;
        }

        public async Task<Guid> Handle(CreateScanCommand request, CancellationToken cancellationToken)
        {
            // 1. Create or Get Target
            // In a real app, we'd check if it exists. For now, create new.
            var target = new Target
            {
                Url = request.Url,
                OwnerId = request.OwnerId,
                IsVerified = true // Assume verified for demo
            };
            await _targetRepository.AddAsync(target);

            // 2. Create ScanJob
            var scanJob = new ScanJob
            {
                TargetId = target.Id,
                ScanProfileId = request.ProfileId,
                Status = ScanStatus.Queued,
                StartTime = DateTime.UtcNow
            };
            await _scanJobRepository.AddAsync(scanJob);

            // 3. Trigger Scan Engine (Fire and Forget or Background Job)
            // We await the start signal, but the engine should run asynchronously.
            await _scanEngine.StartScanAsync(scanJob.Id);

            return scanJob.Id;
        }
    }
}
