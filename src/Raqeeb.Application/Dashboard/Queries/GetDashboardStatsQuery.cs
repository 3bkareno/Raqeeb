using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Dashboard.Queries;

public record GetDashboardStatsQuery : IRequest<DashboardStatsDto>;

public record DashboardStatsDto(
    int TotalTargets,
    int TotalScans,
    int ActiveScans,
    int TotalVulnerabilities,
    int CriticalCount,
    int HighCount,
    int MediumCount,
    int LowCount,
    int InfoCount,
    IEnumerable<RecentScanDto> RecentScans);

public record RecentScanDto(
    Guid Id,
    string TargetUrl,
    string Status,
    DateTime StartTime,
    int VulnerabilityCount);

public class GetDashboardStatsQueryHandler : IRequestHandler<GetDashboardStatsQuery, DashboardStatsDto>
{
    private readonly IRepository<Target> _targetRepository;
    private readonly IRepository<ScanJob> _scanJobRepository;
    private readonly IRepository<Vulnerability> _vulnerabilityRepository;

    public GetDashboardStatsQueryHandler(
        IRepository<Target> targetRepository,
        IRepository<ScanJob> scanJobRepository,
        IRepository<Vulnerability> vulnerabilityRepository)
    {
        _targetRepository = targetRepository;
        _scanJobRepository = scanJobRepository;
        _vulnerabilityRepository = vulnerabilityRepository;
    }

    public async Task<DashboardStatsDto> Handle(GetDashboardStatsQuery request, CancellationToken cancellationToken)
    {
        var targets = await _targetRepository.GetAllAsync();
        var scans = await _scanJobRepository.GetAllAsync();
        var vulnerabilities = await _vulnerabilityRepository.GetAllAsync();

        var scansList = scans.ToList();
        var vulnList = vulnerabilities.ToList();

        var recentScans = scansList
            .OrderByDescending(s => s.StartTime)
            .Take(5)
            .Select(s => new RecentScanDto(
                s.Id,
                s.Target?.Url ?? "",
                s.Status.ToString(),
                s.StartTime,
                s.Vulnerabilities.Count));

        return new DashboardStatsDto(
            targets.Count(),
            scansList.Count,
            scansList.Count(s => s.Status == ScanStatus.Running || s.Status == ScanStatus.Queued),
            vulnList.Count,
            vulnList.Count(v => v.Severity == Severity.Critical),
            vulnList.Count(v => v.Severity == Severity.High),
            vulnList.Count(v => v.Severity == Severity.Medium),
            vulnList.Count(v => v.Severity == Severity.Low),
            vulnList.Count(v => v.Severity == Severity.Info),
            recentScans);
    }
}
