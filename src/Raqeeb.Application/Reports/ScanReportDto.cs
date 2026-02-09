namespace Raqeeb.Application.Reports;

/// <summary>
/// Represents a complete scan report with risk scoring and vulnerability details.
/// </summary>
public record ScanReportDto
{
    public Guid ScanId { get; init; }
    public string TargetUrl { get; init; } = string.Empty;
    public string ProfileName { get; init; } = string.Empty;
    public DateTime StartTime { get; init; }
    public DateTime? EndTime { get; init; }
    public string Status { get; init; } = string.Empty;
    public TimeSpan Duration => EndTime.HasValue ? EndTime.Value - StartTime : TimeSpan.Zero;
    
    // Risk Scoring
    public double RiskScore { get; init; }
    public string RiskLevel { get; init; } = string.Empty;
    
    // Vulnerability Summary
    public int TotalVulnerabilities { get; init; }
    public int CriticalCount { get; init; }
    public int HighCount { get; init; }
    public int MediumCount { get; init; }
    public int LowCount { get; init; }
    public int InfoCount { get; init; }
    
    // Detailed Findings
    public IEnumerable<VulnerabilityReportDto> Vulnerabilities { get; init; } = [];
    
    // Metadata
    public DateTime GeneratedAt { get; init; } = DateTime.UtcNow;
    public string GeneratedBy { get; init; } = "Raqeeb Vulnerability Scanner";
    public string Version { get; init; } = "1.0.0";
}

public record VulnerabilityReportDto
{
    public Guid Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string Severity { get; init; } = string.Empty;
    public int SeverityScore { get; init; }
    public string Url { get; init; } = string.Empty;
    public string Evidence { get; init; } = string.Empty;
    public string Remediation { get; init; } = string.Empty;
    
    // Compliance Mapping
    public string? OwaspCategory { get; init; }
    public string? CweId { get; init; }
    public string? CvssScore { get; init; }
}
