using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Targets.Queries;

public record GetAllTargetsQuery : IRequest<IEnumerable<TargetDto>>;

public record TargetDto(
    Guid Id,
    string Url,
    Guid? OwnerId,
    DateTime CreatedAt,
    bool IsVerified,
    int ScanCount);

public class GetAllTargetsQueryHandler : IRequestHandler<GetAllTargetsQuery, IEnumerable<TargetDto>>
{
    private readonly IRepository<Target> _targetRepository;

    public GetAllTargetsQueryHandler(IRepository<Target> targetRepository)
    {
        _targetRepository = targetRepository;
    }

    public async Task<IEnumerable<TargetDto>> Handle(GetAllTargetsQuery request, CancellationToken cancellationToken)
    {
        var targets = await _targetRepository.GetAllAsync();
        return targets.Select(t => new TargetDto(
            t.Id,
            t.Url,
            t.OwnerId,
            t.CreatedAt,
            t.IsVerified,
            t.ScanJobs.Count));
    }
}
