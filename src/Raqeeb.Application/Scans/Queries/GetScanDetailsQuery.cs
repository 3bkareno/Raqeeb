using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Scans.Queries;

public record GetScanDetailsQuery(Guid ScanId) : IRequest<ScanDetailsDto?>;

public record ScanDetailsDto(
    Guid Id,
    string TargetUrl,
    string ProfileName,
    string Status,
    DateTime StartTime,
    DateTime? EndTime,
    IEnumerable<VulnerabilityDto> Vulnerabilities);

public record VulnerabilityDto(
    Guid Id,
    string Name,
    string Description,
    string Severity,
    string Evidence,
    string Remediation,
    string Url);

public class GetScanDetailsQueryHandler : IRequestHandler<GetScanDetailsQuery, ScanDetailsDto?>
{
    private readonly IRepository<ScanJob> _scanJobRepository;
    private readonly IRepository<Vulnerability> _vulnerabilityRepository;

    public GetScanDetailsQueryHandler(
        IRepository<ScanJob> scanJobRepository,
        IRepository<Vulnerability> vulnerabilityRepository)
    {
        _scanJobRepository = scanJobRepository;
        _vulnerabilityRepository = vulnerabilityRepository;
    }

    public async Task<ScanDetailsDto?> Handle(GetScanDetailsQuery request, CancellationToken cancellationToken)
    {
        var scan = await _scanJobRepository.GetByIdAsync(request.ScanId);
        if (scan == null) return null;

        var vulnerabilities = await _vulnerabilityRepository.FindAsync(v => v.ScanJobId == request.ScanId);

        return new ScanDetailsDto(
            scan.Id,
            scan.Target?.Url ?? "",
            scan.ScanProfile?.Name ?? "Default",
            scan.Status.ToString(),
            scan.StartTime,
            scan.EndTime,
            vulnerabilities.Select(v => new VulnerabilityDto(
                v.Id,
                v.Name,
                v.Description,
                v.Severity.ToString(),
                v.Evidence,
                v.Remediation,
                v.Url)));
    }
}
