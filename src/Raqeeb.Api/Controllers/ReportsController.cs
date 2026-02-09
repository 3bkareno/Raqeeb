using System.Text;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using Raqeeb.Application.Reports;
using Raqeeb.Application.Reports.Queries;

namespace Raqeeb.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ReportsController : ControllerBase
{
    private readonly IMediator _mediator;
    private readonly IReportGenerator _reportGenerator;

    public ReportsController(IMediator mediator, IReportGenerator reportGenerator)
    {
        _mediator = mediator;
        _reportGenerator = reportGenerator;
    }

    /// <summary>
    /// Get scan report data as JSON.
    /// </summary>
    [HttpGet("{scanId}")]
    public async Task<IActionResult> GetReport(Guid scanId)
    {
        var report = await _mediator.Send(new GetScanReportQuery(scanId));
        if (report == null) return NotFound();
        return Ok(report);
    }

    /// <summary>
    /// Download scan report as JSON file.
    /// </summary>
    [HttpGet("{scanId}/download/json")]
    public async Task<IActionResult> DownloadJsonReport(Guid scanId)
    {
        var report = await _mediator.Send(new GetScanReportQuery(scanId));
        if (report == null) return NotFound();

        var json = await _reportGenerator.GenerateJsonReportAsync(report);
        var bytes = Encoding.UTF8.GetBytes(json);
        var fileName = $"raqeeb-scan-{scanId:N}-{DateTime.UtcNow:yyyyMMdd}.json";
        
        return File(bytes, "application/json", fileName);
    }

    /// <summary>
    /// Download scan report as HTML file.
    /// </summary>
    [HttpGet("{scanId}/download/html")]
    public async Task<IActionResult> DownloadHtmlReport(Guid scanId)
    {
        var report = await _mediator.Send(new GetScanReportQuery(scanId));
        if (report == null) return NotFound();

        var html = await _reportGenerator.GenerateHtmlReportAsync(report);
        var bytes = Encoding.UTF8.GetBytes(html);
        var fileName = $"raqeeb-scan-{scanId:N}-{DateTime.UtcNow:yyyyMMdd}.html";
        
        return File(bytes, "text/html", fileName);
    }

    /// <summary>
    /// View HTML report in browser.
    /// </summary>
    [HttpGet("{scanId}/view")]
    public async Task<IActionResult> ViewHtmlReport(Guid scanId)
    {
        var report = await _mediator.Send(new GetScanReportQuery(scanId));
        if (report == null) return NotFound();

        var html = await _reportGenerator.GenerateHtmlReportAsync(report);
        return Content(html, "text/html");
    }

    /// <summary>
    /// Download scan report as PDF file.
    /// </summary>
    [HttpGet("{scanId}/download/pdf")]
    public async Task<IActionResult> DownloadPdfReport(Guid scanId)
    {
        var report = await _mediator.Send(new GetScanReportQuery(scanId));
        if (report == null) return NotFound();

        var pdf = await _reportGenerator.GeneratePdfReportAsync(report);
        var fileName = $"raqeeb-scan-{scanId:N}-{DateTime.UtcNow:yyyyMMdd}.pdf";
        
        return File(pdf, "application/pdf", fileName);
    }

    /// <summary>
    /// Download scan report as Excel file.
    /// </summary>
    [HttpGet("{scanId}/download/excel")]
    public async Task<IActionResult> DownloadExcelReport(Guid scanId)
    {
        var report = await _mediator.Send(new GetScanReportQuery(scanId));
        if (report == null) return NotFound();

        var excel = await _reportGenerator.GenerateExcelReportAsync(report);
        var fileName = $"raqeeb-scan-{scanId:N}-{DateTime.UtcNow:yyyyMMdd}.xlsx";
        
        return File(excel, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", fileName);
    }
}
