using System.Globalization;
using Microsoft.AspNetCore.Localization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Raqeeb.Application.Reports;
using Raqeeb.Application.Scans.Commands;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Infrastructure.Jobs;
using Raqeeb.Infrastructure.Notifications;
using Raqeeb.Infrastructure.Persistence;
using Raqeeb.Infrastructure.Reporting;
using Raqeeb.Infrastructure.Scanning;
using Raqeeb.Infrastructure.Scanning.Modules;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddOpenApi();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Domain & Infrastructure
builder.Services.AddDbContext<RaqeebDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection") ?? "Server=(localdb)\\mssqllocaldb;Database=Raqeeb;Trusted_Connection=True;MultipleActiveResultSets=true"));

builder.Services.AddScoped(typeof(IRepository<>), typeof(EfRepository<>));
builder.Services.AddSingleton<IScanEngine, ScanEngine>();
builder.Services.AddSingleton<IHttpCrawler, HttpCrawler>();

// Scanner Modules - Register all available scanners
builder.Services.AddTransient<IScannerModule, HeaderSecurityScanner>();
builder.Services.AddTransient<IScannerModule, XssScanner>();
builder.Services.AddTransient<IScannerModule, SqlInjectionScanner>();
builder.Services.AddTransient<IScannerModule, CorsScanner>();
builder.Services.AddTransient<IScannerModule, ClickjackingScanner>();
builder.Services.AddTransient<IScannerModule, SslTlsScanner>();
builder.Services.AddTransient<IScannerModule, OpenRedirectScanner>();
builder.Services.AddTransient<IScannerModule, CsrfScanner>();
builder.Services.AddTransient<IScannerModule, SsrfScanner>();
builder.Services.AddTransient<IScannerModule, HttpMethodScanner>();
builder.Services.AddTransient<IScannerModule, DirectoryTraversalScanner>();
builder.Services.AddTransient<IScannerModule, InformationDisclosureScanner>();
builder.Services.AddTransient<IScannerModule, SessionSecurityScanner>();
builder.Services.AddTransient<IScannerModule, DirectoryBruteforceScanner>();
builder.Services.AddTransient<IScannerModule, SubdomainEnumerationScanner>();
builder.Services.AddTransient<IScannerModule, PortScanner>();
builder.Services.AddTransient<IScannerModule, CommandInjectionScanner>();
builder.Services.AddTransient<IScannerModule, XxeScanner>();
builder.Services.AddTransient<IScannerModule, JwtSecurityScanner>();
builder.Services.AddTransient<IScannerModule, IdorScanner>();
builder.Services.AddTransient<IScannerModule, FileUploadScanner>();
builder.Services.AddTransient<IScannerModule, LdapInjectionScanner>();

builder.Services.AddSingleton<IReportGenerator, ReportGenerator>();

// Phase 3: Notification and Scheduling Services
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<INotificationService, NotificationService>();
builder.Services.AddScoped<IWebhookService, WebhookService>();
builder.Services.AddScoped<IScheduleService, ScheduleService>();
builder.Services.AddScoped<ScanJobProcessor>();

builder.Services.AddHttpClient();

// Application (MediatR)
builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(CreateScanCommand).Assembly));

// Localization
builder.Services.AddLocalization();
builder.Services.Configure<RequestLocalizationOptions>(options =>
{
    var supportedCultures = new[] { new CultureInfo("en-US"), new CultureInfo("ar-SA") };
    options.DefaultRequestCulture = new RequestCulture("en-US");
    options.SupportedCultures = supportedCultures;
    options.SupportedUICultures = supportedCultures;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseRequestLocalization();
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
