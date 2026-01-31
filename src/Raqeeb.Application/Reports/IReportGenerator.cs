namespace Raqeeb.Application.Reports;

/// <summary>
/// Interface for generating scan reports in various formats.
/// </summary>
public interface IReportGenerator
{
    /// <summary>
    /// Generates a JSON report for a scan.
    /// </summary>
    Task<string> GenerateJsonReportAsync(ScanReportDto report);
    
    /// <summary>
    /// Generates an HTML report for a scan.
    /// </summary>
    Task<string> GenerateHtmlReportAsync(ScanReportDto report);
}
