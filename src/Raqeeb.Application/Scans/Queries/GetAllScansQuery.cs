using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Scans.Queries;

public record GetAllScansQuery : IRequest<IEnumerable<ScanJobDto>>;

public record ScanJobDto(
    Guid Id,
    Guid TargetId,
    string TargetUrl,
    Guid ScanProfileId,
    string ProfileName,
    string Status,
    DateTime StartTime,
    DateTime? EndTime,
    int VulnerabilityCount);

public class GetAllScansQueryHandler : IRequestHandler<GetAllScansQuery, IEnumerable<ScanJobDto>>
{
    private readonly IRepository<ScanJob> _scanJobRepository;

    public GetAllScansQueryHandler(IRepository<ScanJob> scanJobRepository)
    {
        _scanJobRepository = scanJobRepository;
    }

    public async Task<IEnumerable<ScanJobDto>> Handle(GetAllScansQuery request, CancellationToken cancellationToken)
    {
        var scans = await _scanJobRepository.GetAllAsync();
        return scans.Select(s => new ScanJobDto(
            s.Id,
            s.TargetId,
            s.Target?.Url ?? "",
            s.ScanProfileId,
            s.ScanProfile?.Name ?? "Default",
            s.Status.ToString(),
            s.StartTime,
            s.EndTime,
            s.Vulnerabilities.Count));
    }
}
