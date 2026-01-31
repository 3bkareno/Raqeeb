using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Reports.Queries;

public record GetScanReportQuery(Guid ScanId) : IRequest<ScanReportDto?>;

public class GetScanReportQueryHandler : IRequestHandler<GetScanReportQuery, ScanReportDto?>
{
    private readonly IRepository<ScanJob> _scanJobRepository;
    private readonly IRepository<Vulnerability> _vulnerabilityRepository;

    public GetScanReportQueryHandler(
        IRepository<ScanJob> scanJobRepository,
        IRepository<Vulnerability> vulnerabilityRepository)
    {
        _scanJobRepository = scanJobRepository;
        _vulnerabilityRepository = vulnerabilityRepository;
    }

    public async Task<ScanReportDto?> Handle(GetScanReportQuery request, CancellationToken cancellationToken)
    {
        var scan = await _scanJobRepository.GetByIdAsync(request.ScanId);
        if (scan == null) return null;

        var vulnerabilities = await _vulnerabilityRepository.FindAsync(v => v.ScanJobId == request.ScanId);
        var vulnList = vulnerabilities.ToList();

        var criticalCount = vulnList.Count(v => v.Severity == Severity.Critical);
        var highCount = vulnList.Count(v => v.Severity == Severity.High);
        var mediumCount = vulnList.Count(v => v.Severity == Severity.Medium);
        var lowCount = vulnList.Count(v => v.Severity == Severity.Low);
        var infoCount = vulnList.Count(v => v.Severity == Severity.Info);

        // Calculate risk score (0-100)
        var riskScore = CalculateRiskScore(criticalCount, highCount, mediumCount, lowCount);
        var riskLevel = GetRiskLevel(riskScore);

        return new ScanReportDto
        {
            ScanId = scan.Id,
            TargetUrl = scan.Target?.Url ?? "",
            ProfileName = scan.ScanProfile?.Name ?? "Default",
            StartTime = scan.StartTime,
            EndTime = scan.EndTime,
            Status = scan.Status.ToString(),
            RiskScore = riskScore,
            RiskLevel = riskLevel,
            TotalVulnerabilities = vulnList.Count,
            CriticalCount = criticalCount,
            HighCount = highCount,
            MediumCount = mediumCount,
            LowCount = lowCount,
            InfoCount = infoCount,
            Vulnerabilities = vulnList.Select(v => new VulnerabilityReportDto
            {
                Id = v.Id,
                Name = v.Name,
                Description = v.Description,
                Severity = v.Severity.ToString(),
                SeverityScore = GetSeverityScore(v.Severity),
                Url = v.Url,
                Evidence = v.Evidence,
                Remediation = v.Remediation
            }).OrderByDescending(v => v.SeverityScore)
        };
    }

    private static double CalculateRiskScore(int critical, int high, int medium, int low)
    {
        // Weighted scoring: Critical=40, High=25, Medium=10, Low=2
        var rawScore = (critical * 40) + (high * 25) + (medium * 10) + (low * 2);
        // Normalize to 0-100 scale (cap at 100)
        return Math.Min(rawScore, 100);
    }

    private static string GetRiskLevel(double score) => score switch
    {
        >= 75 => "Critical",
        >= 50 => "High",
        >= 25 => "Medium",
        > 0 => "Low",
        _ => "None"
    };

    private static int GetSeverityScore(Severity severity) => severity switch
    {
        Severity.Critical => 5,
        Severity.High => 4,
        Severity.Medium => 3,
        Severity.Low => 2,
        Severity.Info => 1,
        _ => 0
    };
}
