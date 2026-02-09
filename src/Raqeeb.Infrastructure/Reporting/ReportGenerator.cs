using System.Text;
using System.Text.Json;
using OfficeOpenXml;
using OfficeOpenXml.Style;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using Raqeeb.Application.Reports;

namespace Raqeeb.Infrastructure.Reporting;

/// <summary>
/// Generates scan reports in HTML, JSON, PDF, and Excel formats.
/// </summary>
public class ReportGenerator : IReportGenerator
{
    static ReportGenerator()
    {
        // Set QuestPDF license
        QuestPDF.Settings.License = LicenseType.Community;
        
        // Set EPPlus license (for non-commercial use)
        ExcelPackage.LicenseContext = LicenseContext.NonCommercial;
    }
    
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public Task<string> GenerateJsonReportAsync(ScanReportDto report)
    {
        var json = JsonSerializer.Serialize(report, JsonOptions);
        return Task.FromResult(json);
    }

    public Task<string> GenerateHtmlReportAsync(ScanReportDto report)
    {
        var html = GenerateHtml(report);
        return Task.FromResult(html);
    }

    public Task<byte[]> GeneratePdfReportAsync(ScanReportDto report)
    {
        var document = Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(2, Unit.Centimetre);
                page.DefaultTextStyle(x => x.FontSize(10).FontFamily("Arial"));

                page.Header().Element(c => ComposeHeader(c, report));
                page.Content().Element(c => ComposeContent(c, report));
                page.Footer().Element(c => ComposeFooter(c, report));
            });
        });

        return Task.FromResult(document.GeneratePdf());
    }

    public Task<byte[]> GenerateExcelReportAsync(ScanReportDto report)
    {
        using var package = new ExcelPackage();
        var worksheet = package.Workbook.Worksheets.Add("Scan Report");

        ComposeExcelReport(worksheet, report);

        return Task.FromResult(package.GetAsByteArray());
    }

    private static string GenerateHtml(ScanReportDto report)
    {
        var sb = new StringBuilder();
        
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"  <title>Scan Report - {report.TargetUrl}</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine(GetReportStyles());
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        
        // Header
        sb.AppendLine("  <div class=\"header\">");
        sb.AppendLine("    <div class=\"logo\">??? Raqeeb</div>");
        sb.AppendLine("    <h1>Vulnerability Scan Report</h1>");
        sb.AppendLine($"    <p class=\"generated\">Generated: {report.GeneratedAt:MMMM dd, yyyy HH:mm:ss} UTC</p>");
        sb.AppendLine("  </div>");
        
        // Summary Section
        sb.AppendLine("  <div class=\"section\">");
        sb.AppendLine("    <h2>Executive Summary</h2>");
        sb.AppendLine("    <div class=\"summary-grid\">");
        sb.AppendLine("      <div class=\"summary-item\">");
        sb.AppendLine("        <span class=\"label\">Target</span>");
        sb.AppendLine($"        <span class=\"value\">{report.TargetUrl}</span>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <div class=\"summary-item\">");
        sb.AppendLine("        <span class=\"label\">Profile</span>");
        sb.AppendLine($"        <span class=\"value\">{report.ProfileName}</span>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <div class=\"summary-item\">");
        sb.AppendLine("        <span class=\"label\">Status</span>");
        sb.AppendLine($"        <span class=\"value status-{report.Status.ToLower()}\">{report.Status}</span>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <div class=\"summary-item\">");
        sb.AppendLine("        <span class=\"label\">Duration</span>");
        sb.AppendLine($"        <span class=\"value\">{FormatDuration(report.Duration)}</span>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");

        // Risk Score Section
        sb.AppendLine("  <div class=\"section risk-section\">");
        sb.AppendLine("    <h2>Risk Assessment</h2>");
        sb.AppendLine("    <div class=\"risk-display\">");
        sb.AppendLine($"      <div class=\"risk-score risk-{report.RiskLevel.ToLower()}\">");
        sb.AppendLine($"        <span class=\"score\">{report.RiskScore:F0}</span>");
        sb.AppendLine($"        <span class=\"level\">{report.RiskLevel} Risk</span>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <div class=\"vulnerability-counts\">");
        sb.AppendLine($"        <div class=\"count critical\"><span>{report.CriticalCount}</span> Critical</div>");
        sb.AppendLine($"        <div class=\"count high\"><span>{report.HighCount}</span> High</div>");
        sb.AppendLine($"        <div class=\"count medium\"><span>{report.MediumCount}</span> Medium</div>");
        sb.AppendLine($"        <div class=\"count low\"><span>{report.LowCount}</span> Low</div>");
        sb.AppendLine($"        <div class=\"count info\"><span>{report.InfoCount}</span> Info</div>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");

        // Vulnerabilities Section
        sb.AppendLine("  <div class=\"section\">");
        sb.AppendLine($"    <h2>Vulnerabilities ({report.TotalVulnerabilities})</h2>");
        
        if (report.TotalVulnerabilities == 0)
        {
            sb.AppendLine("    <div class=\"no-vulns\">");
            sb.AppendLine("      <p>? No vulnerabilities were detected during this scan.</p>");
            sb.AppendLine("    </div>");
        }
        else
        {
            foreach (var vuln in report.Vulnerabilities)
            {
                sb.AppendLine($"    <div class=\"vulnerability severity-{vuln.Severity.ToLower()}\">");
                sb.AppendLine($"      <div class=\"vuln-header\">");
                sb.AppendLine($"        <span class=\"severity-badge\">{vuln.Severity}</span>");
                sb.AppendLine($"        <h3>{vuln.Name}</h3>");
                sb.AppendLine($"      </div>");
                sb.AppendLine($"      <p class=\"description\">{vuln.Description}</p>");
                sb.AppendLine($"      <div class=\"vuln-details\">");
                sb.AppendLine($"        <div class=\"detail\"><strong>URL:</strong> <code>{vuln.Url}</code></div>");
                if (!string.IsNullOrEmpty(vuln.OwaspCategory))
                {
                    sb.AppendLine($"        <div class=\"detail\"><strong>OWASP:</strong> <span class=\"compliance-tag\">{vuln.OwaspCategory}</span></div>");
                }
                if (!string.IsNullOrEmpty(vuln.CweId))
                {
                    sb.AppendLine($"        <div class=\"detail\"><strong>CWE:</strong> <span class=\"compliance-tag\">{vuln.CweId}</span></div>");
                }
                if (!string.IsNullOrEmpty(vuln.CvssScore))
                {
                    sb.AppendLine($"        <div class=\"detail\"><strong>CVSS Score:</strong> {vuln.CvssScore}</div>");
                }
                if (!string.IsNullOrEmpty(vuln.Evidence))
                {
                    sb.AppendLine($"        <div class=\"detail\"><strong>Evidence:</strong><pre>{vuln.Evidence}</pre></div>");
                }
                if (!string.IsNullOrEmpty(vuln.Remediation))
                {
                    sb.AppendLine($"        <div class=\"detail remediation\"><strong>Remediation:</strong><p>{vuln.Remediation}</p></div>");
                }
                sb.AppendLine($"      </div>");
                sb.AppendLine($"    </div>");
            }
        }
        
        sb.AppendLine("  </div>");

        // Footer
        sb.AppendLine("  <div class=\"footer\">");
        sb.AppendLine($"    <p>Report generated by {report.GeneratedBy} v{report.Version}</p>");
        sb.AppendLine($"    <p>Scan ID: {report.ScanId}</p>");
        sb.AppendLine("  </div>");

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    private static string GetReportStyles() => """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', system-ui, sans-serif; 
            line-height: 1.6; 
            color: #1e293b;
            background: #f8fafc;
            padding: 2rem;
        }
        .header {
            background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }
        .header .logo { font-size: 1.5rem; margin-bottom: 0.5rem; }
        .header h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .header .generated { opacity: 0.8; }
        .section {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .section h2 { 
            color: #1e293b; 
            margin-bottom: 1rem; 
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #e2e8f0;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .summary-item {
            display: flex;
            flex-direction: column;
            padding: 1rem;
            background: #f8fafc;
            border-radius: 8px;
        }
        .summary-item .label { font-size: 0.875rem; color: #64748b; margin-bottom: 0.25rem; }
        .summary-item .value { font-weight: 600; font-size: 1.125rem; }
        .risk-display {
            display: flex;
            align-items: center;
            gap: 2rem;
            flex-wrap: wrap;
        }
        .risk-score {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: white;
        }
        .risk-score .score { font-size: 3rem; font-weight: 700; line-height: 1; }
        .risk-score .level { font-size: 0.875rem; }
        .risk-critical { background: linear-gradient(135deg, #dc2626, #991b1b); }
        .risk-high { background: linear-gradient(135deg, #ea580c, #c2410c); }
        .risk-medium { background: linear-gradient(135deg, #f59e0b, #d97706); }
        .risk-low { background: linear-gradient(135deg, #3b82f6, #2563eb); }
        .risk-none { background: linear-gradient(135deg, #22c55e, #16a34a); }
        .vulnerability-counts {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }
        .count {
            padding: 0.75rem 1rem;
            border-radius: 8px;
            text-align: center;
            min-width: 80px;
        }
        .count span { display: block; font-size: 1.5rem; font-weight: 700; }
        .count.critical { background: #fef2f2; color: #dc2626; }
        .count.high { background: #fff7ed; color: #ea580c; }
        .count.medium { background: #fffbeb; color: #d97706; }
        .count.low { background: #eff6ff; color: #3b82f6; }
        .count.info { background: #f8fafc; color: #64748b; }
        .vulnerability {
            border-left: 4px solid;
            padding: 1rem;
            margin-bottom: 1rem;
            background: #f8fafc;
            border-radius: 0 8px 8px 0;
        }
        .vulnerability.severity-critical { border-color: #dc2626; }
        .vulnerability.severity-high { border-color: #ea580c; }
        .vulnerability.severity-medium { border-color: #f59e0b; }
        .vulnerability.severity-low { border-color: #3b82f6; }
        .vulnerability.severity-info { border-color: #64748b; }
        .vuln-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
        .vuln-header h3 { font-size: 1.125rem; }
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }
        .severity-critical .severity-badge { background: #dc2626; }
        .severity-high .severity-badge { background: #ea580c; }
        .severity-medium .severity-badge { background: #f59e0b; }
        .severity-low .severity-badge { background: #3b82f6; }
        .severity-info .severity-badge { background: #64748b; }
        .description { color: #475569; margin-bottom: 1rem; }
        .compliance-tag {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            background: #dbeafe;
            color: #1e40af;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        .vuln-details { font-size: 0.875rem; }
        .detail { margin-bottom: 0.5rem; }
        .detail code { background: #1e293b; color: #e2e8f0; padding: 0.25rem 0.5rem; border-radius: 4px; }
        .detail pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 4px; overflow-x: auto; margin-top: 0.5rem; }
        .remediation { background: #f0fdf4; padding: 1rem; border-radius: 8px; border: 1px solid #bbf7d0; }
        .remediation p { color: #166534; }
        .no-vulns {
            text-align: center;
            padding: 2rem;
            background: #f0fdf4;
            border-radius: 8px;
            color: #166534;
        }
        .footer {
            text-align: center;
            padding: 1rem;
            color: #64748b;
            font-size: 0.875rem;
        }
        @media print {
            body { padding: 0; background: white; }
            .section { box-shadow: none; border: 1px solid #e2e8f0; }
        }
        """;

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalHours >= 1)
            return $"{(int)duration.TotalHours}h {duration.Minutes}m {duration.Seconds}s";
        if (duration.TotalMinutes >= 1)
            return $"{(int)duration.TotalMinutes}m {duration.Seconds}s";
        return $"{(int)duration.TotalSeconds}s";
    }

    // PDF Generation Helpers
    private static void ComposeHeader(IContainer container, ScanReportDto report)
    {
        container.Row(row =>
        {
            row.RelativeItem().Column(column =>
            {
                column.Item().Text("👁️ Raqeeb").FontSize(20).SemiBold();
                column.Item().Text("Vulnerability Scan Report").FontSize(16).Bold();
                column.Item().Text($"Generated: {report.GeneratedAt:MMMM dd, yyyy HH:mm:ss} UTC").FontSize(10).FontColor(Colors.Grey.Medium);
            });
        });
    }

    private static void ComposeContent(IContainer container, ScanReportDto report)
    {
        container.PaddingVertical(10).Column(column =>
        {
            column.Spacing(15);

            // Executive Summary
            column.Item().Element(c => ComposeSummarySection(c, report));

            // Risk Assessment
            column.Item().Element(c => ComposeRiskSection(c, report));

            // Vulnerabilities
            column.Item().Element(c => ComposeVulnerabilitiesSection(c, report));
        });
    }

    private static void ComposeSummarySection(IContainer container, ScanReportDto report)
    {
        container.Column(column =>
        {
            column.Item().Text("Executive Summary").FontSize(14).Bold();
            column.Item().PaddingTop(5).Table(table =>
            {
                table.ColumnsDefinition(columns =>
                {
                    columns.RelativeColumn(1);
                    columns.RelativeColumn(2);
                });

                table.Cell().BorderBottom(1).Padding(5).Text("Target:").SemiBold();
                table.Cell().BorderBottom(1).Padding(5).Text(report.TargetUrl);

                table.Cell().BorderBottom(1).Padding(5).Text("Profile:").SemiBold();
                table.Cell().BorderBottom(1).Padding(5).Text(report.ProfileName);

                table.Cell().BorderBottom(1).Padding(5).Text("Status:").SemiBold();
                table.Cell().BorderBottom(1).Padding(5).Text(report.Status);

                table.Cell().Padding(5).Text("Duration:").SemiBold();
                table.Cell().Padding(5).Text(FormatDuration(report.Duration));
            });
        });
    }

    private static void ComposeRiskSection(IContainer container, ScanReportDto report)
    {
        container.Column(column =>
        {
            column.Item().Text("Risk Assessment").FontSize(14).Bold();
            column.Item().PaddingTop(5).Row(row =>
            {
                row.RelativeItem().Column(col =>
                {
                    col.Item().Text($"Risk Score: {report.RiskScore:F0}/100").FontSize(12).SemiBold();
                    col.Item().Text($"Risk Level: {report.RiskLevel}").FontSize(12)
                        .FontColor(report.RiskLevel switch
                        {
                            "Critical" => Colors.Red.Darken2,
                            "High" => Colors.Orange.Darken2,
                            "Medium" => Colors.Yellow.Darken2,
                            "Low" => Colors.Blue.Medium,
                            _ => Colors.Green.Medium
                        });
                });

                row.RelativeItem().Column(col =>
                {
                    col.Item().Text($"Critical: {report.CriticalCount}").FontColor(Colors.Red.Darken2);
                    col.Item().Text($"High: {report.HighCount}").FontColor(Colors.Orange.Darken2);
                    col.Item().Text($"Medium: {report.MediumCount}").FontColor(Colors.Yellow.Darken2);
                    col.Item().Text($"Low: {report.LowCount}").FontColor(Colors.Blue.Medium);
                    col.Item().Text($"Info: {report.InfoCount}").FontColor(Colors.Grey.Medium);
                });
            });
        });
    }

    private static void ComposeVulnerabilitiesSection(IContainer container, ScanReportDto report)
    {
        container.Column(column =>
        {
            column.Item().Text($"Vulnerabilities ({report.TotalVulnerabilities})").FontSize(14).Bold();

            if (report.TotalVulnerabilities == 0)
            {
                column.Item().PaddingTop(10).Text("✓ No vulnerabilities were detected during this scan.")
                    .FontColor(Colors.Green.Medium);
            }
            else
            {
                foreach (var vuln in report.Vulnerabilities)
                {
                    column.Item().PaddingTop(10).BorderLeft(3)
                        .BorderColor(vuln.Severity switch
                        {
                            "Critical" => Colors.Red.Darken2,
                            "High" => Colors.Orange.Darken2,
                            "Medium" => Colors.Yellow.Darken2,
                            "Low" => Colors.Blue.Medium,
                            _ => Colors.Grey.Medium
                        })
                        .Background(Colors.Grey.Lighten4)
                        .Padding(8)
                        .Column(vulnColumn =>
                        {
                            vulnColumn.Item().Row(row =>
                            {
                                row.AutoItem().PaddingRight(5).Text($"[{vuln.Severity}]")
                                    .FontSize(9).SemiBold()
                                    .FontColor(vuln.Severity switch
                                    {
                                        "Critical" => Colors.Red.Darken2,
                                        "High" => Colors.Orange.Darken2,
                                        "Medium" => Colors.Yellow.Darken2,
                                        "Low" => Colors.Blue.Medium,
                                        _ => Colors.Grey.Medium
                                    });
                                row.RelativeItem().Text(vuln.Name).FontSize(11).SemiBold();
                            });

                            vulnColumn.Item().PaddingTop(3).Text(vuln.Description).FontSize(9);

                            vulnColumn.Item().PaddingTop(3).Text($"URL: {vuln.Url}").FontSize(8).Italic();

                            if (!string.IsNullOrEmpty(vuln.OwaspCategory))
                            {
                                vulnColumn.Item().PaddingTop(2).Text($"OWASP: {vuln.OwaspCategory}").FontSize(8).FontColor(Colors.Blue.Darken1);
                            }

                            if (!string.IsNullOrEmpty(vuln.CweId))
                            {
                                vulnColumn.Item().Text($"CWE: {vuln.CweId}").FontSize(8).FontColor(Colors.Blue.Darken1);
                            }

                            if (!string.IsNullOrEmpty(vuln.Remediation))
                            {
                                vulnColumn.Item().PaddingTop(3).Background(Colors.Green.Lighten4)
                                    .Padding(5).Text($"Remediation: {vuln.Remediation}")
                                    .FontSize(8).FontColor(Colors.Green.Darken2);
                            }
                        });
                }
            }
        });
    }

    private static void ComposeFooter(IContainer container, ScanReportDto report)
    {
        container.AlignCenter().Text(text =>
        {
            text.Span($"Report generated by {report.GeneratedBy} v{report.Version} | ");
            text.Span($"Scan ID: {report.ScanId}");
            text.Span($" | Page ").FontSize(9);
            text.CurrentPageNumber().FontSize(9);
        });
    }

    // Excel Generation Helpers
    private static void ComposeExcelReport(ExcelWorksheet worksheet, ScanReportDto report)
    {
        // Set column widths
        worksheet.Column(1).Width = 20;
        worksheet.Column(2).Width = 40;
        worksheet.Column(3).Width = 15;
        worksheet.Column(4).Width = 50;
        worksheet.Column(5).Width = 30;
        worksheet.Column(6).Width = 20;

        int row = 1;

        // Header
        worksheet.Cells[row, 1].Value = "Raqeeb Vulnerability Scan Report";
        worksheet.Cells[row, 1, row, 6].Merge = true;
        worksheet.Cells[row, 1].Style.Font.Size = 16;
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        worksheet.Cells[row, 1].Style.HorizontalAlignment = ExcelHorizontalAlignment.Center;
        row += 2;

        // Summary Section
        worksheet.Cells[row, 1].Value = "Target:";
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        worksheet.Cells[row, 2].Value = report.TargetUrl;
        row++;

        worksheet.Cells[row, 1].Value = "Profile:";
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        worksheet.Cells[row, 2].Value = report.ProfileName;
        row++;

        worksheet.Cells[row, 1].Value = "Status:";
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        worksheet.Cells[row, 2].Value = report.Status;
        row++;

        worksheet.Cells[row, 1].Value = "Duration:";
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        worksheet.Cells[row, 2].Value = FormatDuration(report.Duration);
        row++;

        worksheet.Cells[row, 1].Value = "Generated:";
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        worksheet.Cells[row, 2].Value = report.GeneratedAt.ToString("MMMM dd, yyyy HH:mm:ss");
        row += 2;

        // Risk Assessment
        worksheet.Cells[row, 1].Value = "Risk Assessment";
        worksheet.Cells[row, 1].Style.Font.Size = 14;
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        row++;

        worksheet.Cells[row, 1].Value = "Risk Score:";
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        worksheet.Cells[row, 2].Value = $"{report.RiskScore:F0}/100";
        row++;

        worksheet.Cells[row, 1].Value = "Risk Level:";
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        worksheet.Cells[row, 2].Value = report.RiskLevel;
        worksheet.Cells[row, 2].Style.Font.Color.SetColor(report.RiskLevel switch
        {
            "Critical" => System.Drawing.Color.DarkRed,
            "High" => System.Drawing.Color.DarkOrange,
            "Medium" => System.Drawing.Color.DarkGoldenrod,
            "Low" => System.Drawing.Color.Blue,
            _ => System.Drawing.Color.Green
        });
        row += 2;

        // Vulnerability Counts
        worksheet.Cells[row, 1].Value = "Vulnerability Summary";
        worksheet.Cells[row, 1].Style.Font.Size = 14;
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        row++;

        worksheet.Cells[row, 1].Value = "Critical:";
        worksheet.Cells[row, 2].Value = report.CriticalCount;
        worksheet.Cells[row, 2].Style.Font.Color.SetColor(System.Drawing.Color.DarkRed);
        row++;

        worksheet.Cells[row, 1].Value = "High:";
        worksheet.Cells[row, 2].Value = report.HighCount;
        worksheet.Cells[row, 2].Style.Font.Color.SetColor(System.Drawing.Color.DarkOrange);
        row++;

        worksheet.Cells[row, 1].Value = "Medium:";
        worksheet.Cells[row, 2].Value = report.MediumCount;
        worksheet.Cells[row, 2].Style.Font.Color.SetColor(System.Drawing.Color.DarkGoldenrod);
        row++;

        worksheet.Cells[row, 1].Value = "Low:";
        worksheet.Cells[row, 2].Value = report.LowCount;
        worksheet.Cells[row, 2].Style.Font.Color.SetColor(System.Drawing.Color.Blue);
        row++;

        worksheet.Cells[row, 1].Value = "Info:";
        worksheet.Cells[row, 2].Value = report.InfoCount;
        row += 2;

        // Vulnerabilities Table
        worksheet.Cells[row, 1].Value = "Detailed Vulnerabilities";
        worksheet.Cells[row, 1].Style.Font.Size = 14;
        worksheet.Cells[row, 1].Style.Font.Bold = true;
        row++;

        if (report.TotalVulnerabilities == 0)
        {
            worksheet.Cells[row, 1].Value = "✓ No vulnerabilities were detected during this scan.";
            worksheet.Cells[row, 1].Style.Font.Color.SetColor(System.Drawing.Color.Green);
        }
        else
        {
            // Table Headers
            worksheet.Cells[row, 1].Value = "Severity";
            worksheet.Cells[row, 2].Value = "Name";
            worksheet.Cells[row, 3].Value = "OWASP";
            worksheet.Cells[row, 4].Value = "Description";
            worksheet.Cells[row, 5].Value = "URL";
            worksheet.Cells[row, 6].Value = "CWE";

            using (var range = worksheet.Cells[row, 1, row, 6])
            {
                range.Style.Font.Bold = true;
                range.Style.Fill.PatternType = ExcelFillStyle.Solid;
                range.Style.Fill.BackgroundColor.SetColor(System.Drawing.Color.LightGray);
                range.Style.Border.Bottom.Style = ExcelBorderStyle.Thick;
            }
            row++;

            // Data Rows
            foreach (var vuln in report.Vulnerabilities)
            {
                worksheet.Cells[row, 1].Value = vuln.Severity;
                worksheet.Cells[row, 1].Style.Font.Color.SetColor(vuln.Severity switch
                {
                    "Critical" => System.Drawing.Color.DarkRed,
                    "High" => System.Drawing.Color.DarkOrange,
                    "Medium" => System.Drawing.Color.DarkGoldenrod,
                    "Low" => System.Drawing.Color.Blue,
                    _ => System.Drawing.Color.Gray
                });

                worksheet.Cells[row, 2].Value = vuln.Name;
                worksheet.Cells[row, 3].Value = vuln.OwaspCategory ?? "N/A";
                worksheet.Cells[row, 4].Value = vuln.Description;
                worksheet.Cells[row, 5].Value = vuln.Url;
                worksheet.Cells[row, 6].Value = vuln.CweId ?? "N/A";

                worksheet.Row(row).Style.WrapText = true;
                row++;
            }

            // Auto-fit rows
            worksheet.Cells[worksheet.Dimension.Address].AutoFitColumns();
        }
    }
}
