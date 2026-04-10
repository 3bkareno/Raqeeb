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
        sb.AppendLine("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
""");
        sb.AppendLine($"<title>Raqeeb Scan Report — {EscapeHtml(report.TargetUrl)}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine(GetReportStyles());
        sb.AppendLine("</style></head><body>");

        // ── 1. Scan Details ──
        sb.AppendLine("""
<div class="header">
  <div class="brand"><span class="logo">🛡️</span> Raqeeb Scan Report</div>
</div>
""");
        sb.AppendLine("<div class='section'><h2>1. Scan Details</h2><table class='info-table'>");
        Row("Target", EscapeHtml(report.TargetUrl));
        Row("Profile", EscapeHtml(report.ProfileName));
        Row("Status", report.Status);
        Row("Started", report.StartTime.ToString("MMM dd, yyyy HH:mm:ss"));
        Row("Completed", report.EndTime?.ToString("MMM dd, yyyy HH:mm:ss") ?? "In progress…");
        Row("Duration", FormatDuration(report.Duration));
        Row("Report Date", report.GeneratedAt.ToString("MMMM dd, yyyy HH:mm:ss"));
        Row("Scan ID", report.ScanId.ToString());
        sb.AppendLine("</table></div>");

        // ── 2. Executive Summary ──
        sb.AppendLine("<div class='section'><h2>2. Executive Summary</h2>");
        sb.AppendLine($"<p>{BuildExecutiveSummary(report)}</p>");
        sb.AppendLine("<div class='severity-bar'>");
        SeverityPill("Critical", report.CriticalCount, "#dc2626");
        SeverityPill("High", report.HighCount, "#ea580c");
        SeverityPill("Medium", report.MediumCount, "#d97706");
        SeverityPill("Low", report.LowCount, "#3b82f6");
        SeverityPill("Info", report.InfoCount, "#64748b");
        sb.AppendLine("</div>");
        sb.AppendLine($"<div class='risk-badge risk-{report.RiskLevel.ToLowerInvariant()}'>");
        sb.AppendLine($"<span class='score'>{report.RiskScore:F0}</span><span class='label'>/ 100 — {report.RiskLevel} Risk</span></div>");
        sb.AppendLine("</div>");

        // ── 3. Alerts Summary ──
        sb.AppendLine("<div class='section'><h2>3. Alerts Summary</h2>");
        if (report.TotalVulnerabilities == 0)
        {
            sb.AppendLine("<p class='clean'>✓ No vulnerabilities were detected during this scan.</p>");
        }
        else
        {
            sb.AppendLine("<table class='alerts-table'><thead><tr><th>#</th><th>Severity</th><th>Name</th><th>CWE</th><th>CVSS</th><th>OWASP</th></tr></thead><tbody>");
            int idx = 1;
            foreach (var v in report.Vulnerabilities)
            {
                sb.AppendLine($"<tr><td>{idx++}</td><td><span class='sev sev-{v.Severity.ToLowerInvariant()}'>{v.Severity}</span></td>");
                sb.AppendLine($"<td><a href='#alert-{v.Id}'>{EscapeHtml(v.Name)}</a></td>");
                sb.AppendLine($"<td>{EscapeHtml(v.CweId ?? "—")}</td>");
                sb.AppendLine($"<td>{EscapeHtml(v.CvssScore ?? "—")}</td>");
                sb.AppendLine($"<td>{EscapeHtml(v.OwaspCategory ?? "—")}</td></tr>");
            }
            sb.AppendLine("</tbody></table>");
        }
        sb.AppendLine("</div>");

        // ── 4. Detailed Alerts ──
        sb.AppendLine("<div class='section'><h2>4. Detailed Alerts</h2>");
        foreach (var v in report.Vulnerabilities)
        {
            sb.AppendLine($"<div class='alert-card sev-border-{v.Severity.ToLowerInvariant()}' id='alert-{v.Id}'>");
            sb.AppendLine($"<div class='alert-title'><span class='sev sev-{v.Severity.ToLowerInvariant()}'>{v.Severity}</span><h3>{EscapeHtml(v.Name)}</h3></div>");
            sb.AppendLine("<table class='info-table alert-meta'>");
            Row("CVSS Score", v.CvssScore ?? "—");
            Row("CWE", v.CweId ?? "—");
            Row("OWASP", v.OwaspCategory ?? "—");
            Row("Location / URL", $"<code>{EscapeHtml(v.Url)}</code>");
            if (!string.IsNullOrEmpty(v.AffectedParameter)) Row("Parameter", $"<code>{EscapeHtml(v.AffectedParameter)}</code>");
            if (!string.IsNullOrEmpty(v.ModuleName)) Row("Scanner Module", EscapeHtml(v.ModuleName));
            sb.AppendLine("</table>");

            sb.AppendLine($"<h4>Vulnerability Description</h4><p>{EscapeHtml(v.Description)}</p>");

            if (!string.IsNullOrEmpty(v.Evidence))
            {
                sb.AppendLine($"<h4>Attack Details / Evidence</h4><pre class='evidence'>{EscapeHtml(v.Evidence)}</pre>");
            }

            if (!string.IsNullOrEmpty(v.Remediation))
            {
                sb.AppendLine($"<div class='remediation-box'><h4>Remediation</h4><p>{EscapeHtml(v.Remediation)}</p></div>");
            }

            if (!string.IsNullOrEmpty(v.References))
            {
                sb.AppendLine("<h4>References</h4><ul class='ref-list'>");
                foreach (var link in v.References.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    sb.AppendLine($"<li><a href='{EscapeHtml(link)}' target='_blank'>{EscapeHtml(link)}</a></li>");
                sb.AppendLine("</ul>");
            }
            else if (!string.IsNullOrEmpty(v.CweId))
            {
                var cweNum = v.CweId.Replace("CWE-", "");
                sb.AppendLine("<h4>References</h4><ul class='ref-list'>");
                sb.AppendLine($"<li><a href='https://cwe.mitre.org/data/definitions/{cweNum}.html' target='_blank'>MITRE {v.CweId}</a></li>");
                sb.AppendLine($"<li><a href='https://owasp.org/Top10/' target='_blank'>OWASP Top 10 (2021)</a></li>");
                sb.AppendLine("</ul>");
            }

            sb.AppendLine("</div>"); // end alert-card
        }
        sb.AppendLine("</div>");

        // Footer
        sb.AppendLine($"<div class='footer'>Report generated by {EscapeHtml(report.GeneratedBy)} v{report.Version} &bull; Scan ID: {report.ScanId}</div>");
        sb.AppendLine("</body></html>");
        return sb.ToString();

        void Row(string label, string value) => sb.AppendLine($"<tr><td class='lbl'>{label}</td><td>{value}</td></tr>");
        void SeverityPill(string name, int count, string color) =>
            sb.AppendLine($"<div class='pill' style='border-color:{color};color:{color}'><span class='num'>{count}</span>{name}</div>");
    }

    private static string BuildExecutiveSummary(ScanReportDto r)
    {
        if (r.TotalVulnerabilities == 0)
            return "The scan completed with no security vulnerabilities detected. The target appears to meet baseline security standards.";

        var level = r.RiskLevel;
        return $"The scan discovered <strong>{r.TotalVulnerabilities}</strong> vulnerability finding(s) across the target " +
               $"<code>{EscapeHtml(r.TargetUrl)}</code>. The overall risk level is assessed as <strong>{level}</strong> " +
               $"({r.CriticalCount} Critical, {r.HighCount} High, {r.MediumCount} Medium, {r.LowCount} Low, {r.InfoCount} Informational). " +
               "Immediate remediation is recommended for all Critical and High severity findings.";
    }

    private static string EscapeHtml(string s) =>
        System.Net.WebUtility.HtmlEncode(s ?? "");

    private static string GetReportStyles() => """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;line-height:1.7;color:#1e293b;background:#f8fafc;padding:0}
.header{background:linear-gradient(135deg,#1e1b4b,#312e81);color:#fff;padding:2rem 2.5rem}
.brand{font-size:1.6rem;font-weight:700}
.logo{margin-right:.4rem}
.section{background:#fff;margin:1.5rem 2rem;padding:2rem;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.section h2{font-size:1.25rem;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:.5rem;margin-bottom:1rem}
.section h4{font-size:.95rem;color:#334155;margin:1rem 0 .4rem}
.info-table{width:100%;border-collapse:collapse}
.info-table td{padding:.45rem .6rem;border-bottom:1px solid #f1f5f9;font-size:.9rem;vertical-align:top}
.info-table .lbl{font-weight:600;width:170px;color:#475569}
code{background:#1e293b;color:#e2e8f0;padding:.15rem .45rem;border-radius:4px;font-size:.85rem}
.severity-bar{display:flex;gap:.75rem;flex-wrap:wrap;margin:1rem 0}
.pill{border:2px solid;border-radius:8px;padding:.4rem .9rem;font-weight:600;font-size:.85rem;display:flex;align-items:center;gap:.4rem}
.pill .num{font-size:1.3rem;font-weight:800}
.risk-badge{display:inline-flex;align-items:center;gap:.7rem;padding:.6rem 1.2rem;border-radius:10px;color:#fff;margin-top:.5rem}
.risk-badge .score{font-size:2rem;font-weight:800}.risk-badge .label{font-size:.95rem}
.risk-critical{background:linear-gradient(135deg,#dc2626,#991b1b)}
.risk-high{background:linear-gradient(135deg,#ea580c,#c2410c)}
.risk-medium{background:linear-gradient(135deg,#f59e0b,#d97706)}
.risk-low{background:linear-gradient(135deg,#3b82f6,#2563eb)}
.risk-none{background:linear-gradient(135deg,#22c55e,#16a34a)}
.alerts-table{width:100%;border-collapse:collapse;font-size:.88rem}
.alerts-table th{text-align:left;padding:.55rem .6rem;background:#f1f5f9;border-bottom:2px solid #cbd5e1;font-weight:600}
.alerts-table td{padding:.55rem .6rem;border-bottom:1px solid #f1f5f9}
.alerts-table a{color:#2563eb;text-decoration:none;font-weight:500}
.alerts-table a:hover{text-decoration:underline}
.sev{display:inline-block;padding:.15rem .55rem;border-radius:4px;font-size:.75rem;font-weight:700;color:#fff;text-transform:uppercase}
.sev-critical{background:#dc2626}.sev-high{background:#ea580c}.sev-medium{background:#d97706}.sev-low{background:#3b82f6}.sev-info{background:#64748b}
.alert-card{border-left:5px solid;background:#f8fafc;border-radius:0 10px 10px 0;padding:1.5rem;margin-bottom:1.5rem}
.sev-border-critical{border-color:#dc2626}.sev-border-high{border-color:#ea580c}.sev-border-medium{border-color:#d97706}.sev-border-low{border-color:#3b82f6}.sev-border-info{border-color:#64748b}
.alert-title{display:flex;align-items:center;gap:.75rem;margin-bottom:.8rem}
.alert-title h3{font-size:1.1rem}
.alert-meta{margin-bottom:.8rem}
.evidence{background:#1e293b;color:#e2e8f0;padding:1rem;border-radius:6px;overflow-x:auto;font-size:.82rem;white-space:pre-wrap;word-break:break-all}
.remediation-box{background:#f0fdf4;border:1px solid #bbf7d0;padding:1rem;border-radius:8px;margin-top:.5rem}
.remediation-box h4{color:#166534;margin-top:0}
.remediation-box p{color:#166534;font-size:.9rem}
.ref-list{margin:.3rem 0 0 1.2rem;font-size:.88rem}
.ref-list a{color:#2563eb}
.clean{text-align:center;padding:2rem;background:#f0fdf4;border-radius:8px;color:#166534;font-size:1.05rem}
.footer{text-align:center;padding:1.5rem;color:#94a3b8;font-size:.82rem}
@media print{body{padding:0;background:#fff}.section{box-shadow:none;border:1px solid #e2e8f0;break-inside:avoid}.alert-card{break-inside:avoid}}
""";

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalHours >= 1)
            return $"{(int)duration.TotalHours}h {duration.Minutes}m {duration.Seconds}s";
        if (duration.TotalMinutes >= 1)
            return $"{(int)duration.TotalMinutes}m {duration.Seconds}s";
        return $"{(int)duration.TotalSeconds}s";
    }

    // ───── PDF Generation (Acunetix-style) ─────

    private static void ComposeHeader(IContainer container, ScanReportDto report)
    {
        container.Column(col =>
        {
            col.Item().Background(Colors.Indigo.Darken3).Padding(20).Row(row =>
            {
                row.RelativeItem().Column(c =>
                {
                    c.Item().Text("Raqeeb Scan Report").FontSize(22).Bold().FontColor(Colors.White);
                    c.Item().Text(report.TargetUrl).FontSize(10).FontColor(Colors.Grey.Lighten2);
                });
            });
        });
    }

    private static void ComposeContent(IContainer container, ScanReportDto report)
    {
        container.PaddingVertical(10).Column(column =>
        {
            column.Spacing(15);

            // § 1 — Scan Details
            column.Item().Text("1. Scan Details").FontSize(14).Bold();
            column.Item().Element(c => ComposeScanDetailsTable(c, report));

            // § 2 — Executive Summary
            column.Item().Text("2. Executive Summary").FontSize(14).Bold();
            column.Item().Text(BuildExecutiveSummaryPlain(report)).FontSize(10);
            column.Item().Element(c => ComposeSeverityCounts(c, report));

            // § 3 — Alerts Summary
            column.Item().Text("3. Alerts Summary").FontSize(14).Bold();
            column.Item().Element(c => ComposeAlertsSummaryTable(c, report));

            // § 4 — Detailed Alerts
            column.Item().Text("4. Detailed Alerts").FontSize(14).Bold();
            foreach (var vuln in report.Vulnerabilities)
            {
                column.Item().Element(c => ComposeDetailedAlert(c, vuln));
            }
        });
    }

    private static void ComposeScanDetailsTable(IContainer container, ScanReportDto report)
    {
        container.Table(table =>
        {
            table.ColumnsDefinition(c => { c.RelativeColumn(1); c.RelativeColumn(2); });
            void R(string label, string val)
            {
                table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten3).Padding(4).Text(label).SemiBold().FontSize(9);
                table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten3).Padding(4).Text(val).FontSize(9);
            }
            R("Target", report.TargetUrl);
            R("Profile", report.ProfileName);
            R("Status", report.Status);
            R("Started", report.StartTime.ToString("MMM dd, yyyy HH:mm:ss"));
            R("Completed", report.EndTime?.ToString("MMM dd, yyyy HH:mm:ss") ?? "In progress…");
            R("Duration", FormatDuration(report.Duration));
            R("Report Date", report.GeneratedAt.ToString("MMMM dd, yyyy HH:mm:ss"));
            R("Scan ID", report.ScanId.ToString());
        });
    }

    private static string BuildExecutiveSummaryPlain(ScanReportDto r)
    {
        if (r.TotalVulnerabilities == 0)
            return "The scan completed with no security vulnerabilities detected.";
        return $"The scan discovered {r.TotalVulnerabilities} finding(s). Overall risk: {r.RiskLevel} ({r.RiskScore:F0}/100). " +
               $"{r.CriticalCount} Critical, {r.HighCount} High, {r.MediumCount} Medium, {r.LowCount} Low, {r.InfoCount} Info. " +
               "Immediate remediation is recommended for all Critical and High findings.";
    }

    private static void ComposeSeverityCounts(IContainer container, ScanReportDto report)
    {
        container.Row(row =>
        {
            void Pill(string label, int count, string color)
            {
                row.AutoItem().PaddingRight(10).Border(1).BorderColor(color).Padding(5).Row(r =>
                {
                    r.AutoItem().Text($"{count}").FontSize(12).Bold().FontColor(color);
                    r.AutoItem().PaddingLeft(3).Text(label).FontSize(8).FontColor(color);
                });
            }
            Pill("Critical", report.CriticalCount, Colors.Red.Darken2);
            Pill("High", report.HighCount, Colors.Orange.Darken2);
            Pill("Medium", report.MediumCount, Colors.Yellow.Darken2);
            Pill("Low", report.LowCount, Colors.Blue.Medium);
            Pill("Info", report.InfoCount, Colors.Grey.Medium);
        });
    }

    private static void ComposeAlertsSummaryTable(IContainer container, ScanReportDto report)
    {
        if (report.TotalVulnerabilities == 0)
        {
            container.Text("No vulnerabilities detected.").FontColor(Colors.Green.Medium).FontSize(10);
            return;
        }

        container.Table(table =>
        {
            table.ColumnsDefinition(c =>
            {
                c.ConstantColumn(25);   // #
                c.ConstantColumn(55);   // Severity
                c.RelativeColumn(3);    // Name
                c.ConstantColumn(55);   // CWE
                c.ConstantColumn(40);   // CVSS
            });

            // Header
            table.Header(header =>
            {
                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("#").FontSize(8).SemiBold();
                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Severity").FontSize(8).SemiBold();
                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("Name").FontSize(8).SemiBold();
                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("CWE").FontSize(8).SemiBold();
                header.Cell().Background(Colors.Grey.Lighten3).Padding(4).Text("CVSS").FontSize(8).SemiBold();
            });

            int i = 1;
            foreach (var v in report.Vulnerabilities)
            {
                var sevColor = SeverityColor(v.Severity);
                table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten3).Padding(3).Text($"{i++}").FontSize(8);
                table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten3).Padding(3).Text(v.Severity).FontSize(8).FontColor(sevColor).SemiBold();
                table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten3).Padding(3).Text(v.Name).FontSize(8);
                table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten3).Padding(3).Text(v.CweId ?? "—").FontSize(8);
                table.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten3).Padding(3).Text(v.CvssScore ?? "—").FontSize(8);
            }
        });
    }

    private static void ComposeDetailedAlert(IContainer container, VulnerabilityReportDto v)
    {
        var sevColor = SeverityColor(v.Severity);

        container.PaddingTop(8).BorderLeft(4).BorderColor(sevColor).Background(Colors.Grey.Lighten4).Padding(10).Column(col =>
        {
            // Title
            col.Item().Row(r =>
            {
                r.AutoItem().Background(sevColor).PaddingVertical(3).PaddingHorizontal(6).Text(v.Severity).FontSize(8).Bold().FontColor(Colors.White);
                r.AutoItem().PaddingLeft(8).Text(v.Name).FontSize(11).SemiBold();
            });

            // Meta table
            col.Item().PaddingTop(6).Table(t =>
            {
                t.ColumnsDefinition(c => { c.ConstantColumn(100); c.RelativeColumn(); });
                void R(string l, string val)
                {
                    t.Cell().Padding(2).Text(l).FontSize(8).SemiBold().FontColor(Colors.Grey.Darken1);
                    t.Cell().Padding(2).Text(val).FontSize(8);
                }
                R("CVSS Score", v.CvssScore ?? "—");
                R("CWE", v.CweId ?? "—");
                R("OWASP", v.OwaspCategory ?? "—");
                R("URL", v.Url);
                if (!string.IsNullOrEmpty(v.AffectedParameter)) R("Parameter", v.AffectedParameter);
                if (!string.IsNullOrEmpty(v.ModuleName)) R("Module", v.ModuleName);
            });

            // Description
            col.Item().PaddingTop(6).Text("Vulnerability Description").FontSize(9).SemiBold();
            col.Item().PaddingTop(2).Text(v.Description).FontSize(9);

            // Evidence
            if (!string.IsNullOrEmpty(v.Evidence))
            {
                col.Item().PaddingTop(6).Text("Attack Details / Evidence").FontSize(9).SemiBold();
                col.Item().PaddingTop(2).Background(Colors.Grey.Darken3).Padding(8)
                    .Text(v.Evidence).FontSize(8).FontColor(Colors.Grey.Lighten3);
            }

            // Remediation
            if (!string.IsNullOrEmpty(v.Remediation))
            {
                col.Item().PaddingTop(6).Background(Colors.Green.Lighten4).Padding(8).Column(remCol =>
                {
                    remCol.Item().Text("Remediation").FontSize(9).SemiBold().FontColor(Colors.Green.Darken2);
                    remCol.Item().PaddingTop(2).Text(v.Remediation).FontSize(8).FontColor(Colors.Green.Darken2);
                });
            }

            // References
            if (!string.IsNullOrEmpty(v.CweId))
            {
                var cweNum = v.CweId.Replace("CWE-", "");
                col.Item().PaddingTop(4).Text($"Ref: https://cwe.mitre.org/data/definitions/{cweNum}.html")
                    .FontSize(7).FontColor(Colors.Blue.Medium);
            }
        });
    }

    private static string SeverityColor(string severity) => severity switch
    {
        "Critical" => Colors.Red.Darken2,
        "High" => Colors.Orange.Darken2,
        "Medium" => Colors.Yellow.Darken2,
        "Low" => Colors.Blue.Medium,
        _ => Colors.Grey.Medium
    };

    private static void ComposeFooter(IContainer container, ScanReportDto report)
    {
        container.AlignCenter().Text(text =>
        {
            text.Span($"Raqeeb v{report.Version} | Scan ID: {report.ScanId} | Page ").FontSize(8).FontColor(Colors.Grey.Medium);
            text.CurrentPageNumber().FontSize(8).FontColor(Colors.Grey.Medium);
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
