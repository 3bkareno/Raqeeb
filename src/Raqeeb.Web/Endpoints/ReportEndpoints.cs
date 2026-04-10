using System.Text;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using Raqeeb.Application.Reports;
using Raqeeb.Application.Reports.Queries;

namespace Raqeeb.Web.Endpoints;

/// <summary>
/// Maps report download/view endpoints to the Web application.
/// </summary>
public static class ReportEndpoints
{
    public static void MapReportEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/reports");

        group.MapGet("/{scanId:guid}", async (Guid scanId, IMediator mediator) =>
        {
            var report = await mediator.Send(new GetScanReportQuery(scanId));
            return report is null ? Results.NotFound() : Results.Ok(report);
        });

        group.MapGet("/{scanId:guid}/download/json", async (Guid scanId, IMediator mediator, IReportGenerator generator) =>
        {
            var report = await mediator.Send(new GetScanReportQuery(scanId));
            if (report is null) return Results.NotFound();

            var json = await generator.GenerateJsonReportAsync(report);
            var bytes = Encoding.UTF8.GetBytes(json);
            return Results.File(bytes, "application/json", $"raqeeb-scan-{scanId:N}-{DateTime.UtcNow:yyyyMMdd}.json");
        });

        group.MapGet("/{scanId:guid}/download/html", async (Guid scanId, IMediator mediator, IReportGenerator generator) =>
        {
            var report = await mediator.Send(new GetScanReportQuery(scanId));
            if (report is null) return Results.NotFound();

            var html = await generator.GenerateHtmlReportAsync(report);
            var bytes = Encoding.UTF8.GetBytes(html);
            return Results.File(bytes, "text/html", $"raqeeb-scan-{scanId:N}-{DateTime.UtcNow:yyyyMMdd}.html");
        });

        group.MapGet("/{scanId:guid}/view", async (Guid scanId, IMediator mediator, IReportGenerator generator) =>
        {
            var report = await mediator.Send(new GetScanReportQuery(scanId));
            if (report is null) return Results.NotFound();

            var html = await generator.GenerateHtmlReportAsync(report);
            return Results.Content(html, "text/html");
        });

        group.MapGet("/{scanId:guid}/download/pdf", async (Guid scanId, IMediator mediator, IReportGenerator generator) =>
        {
            var report = await mediator.Send(new GetScanReportQuery(scanId));
            if (report is null) return Results.NotFound();

            var pdf = await generator.GeneratePdfReportAsync(report);
            return Results.File(pdf, "application/pdf", $"raqeeb-scan-{scanId:N}-{DateTime.UtcNow:yyyyMMdd}.pdf");
        });
    }
}
