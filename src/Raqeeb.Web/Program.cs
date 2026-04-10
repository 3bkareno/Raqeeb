using HealthChecks.UI.Client;
using Hangfire;
using Hangfire.SqlServer;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Raqeeb.Application.Scans.Commands;
using Raqeeb.Application.Reports;
using Raqeeb.Domain.Constants;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Infrastructure.Jobs;
using Raqeeb.Infrastructure.Notifications;
using Raqeeb.Infrastructure.Persistence;
using Raqeeb.Infrastructure.Reporting;
using Raqeeb.Infrastructure.Scanning;
using Raqeeb.Infrastructure.Scanning.Modules;
using Raqeeb.Web.Components;
using Raqeeb.Web.Endpoints;
using Raqeeb.Web.Services;
using Serilog;
using System.Threading.RateLimiting;

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.EntityFrameworkCore", Serilog.Events.LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File("logs/raqeeb-.log", 
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

try
{
    Log.Information("Starting Raqeeb application");


    var builder = WebApplication.CreateBuilder(args);

    // Use Serilog
    builder.Host.UseSerilog();

    // Add services to the container.
    builder.Services.AddRazorComponents()
        .AddInteractiveServerComponents();

    // Add cascading authentication state (required for AuthorizeView components)
    builder.Services.AddCascadingAuthenticationState();

    // HttpContext accessor for authentication
    builder.Services.AddHttpContextAccessor();

    // Database
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    builder.Services.AddDbContext<RaqeebDbContext>(options =>
        options.UseSqlServer(connectionString));

    // Hangfire
    builder.Services.AddHangfire(config => config
        .SetDataCompatibilityLevel(CompatibilityLevel.Version_170)
        .UseSimpleAssemblyNameTypeSerializer()
        .UseRecommendedSerializerSettings()
        .UseSqlServerStorage(connectionString));

    builder.Services.AddHangfireServer(options =>
    {
        options.WorkerCount = 2; // Number of concurrent background jobs
        options.Queues = new[] { "default", "high-priority" };
    });

    // Identity
    builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequiredLength = 8;
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = false; // Set to true in production
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;
    })
    .AddEntityFrameworkStores<RaqeebDbContext>()
    .AddDefaultTokenProviders();

    // Configure cookie settings
    builder.Services.ConfigureApplicationCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.AccessDeniedPath = "/access-denied";
        options.ExpireTimeSpan = TimeSpan.FromDays(30);
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });

    // Authentication state provider for Blazor
    builder.Services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider>();

    // Health Checks
    builder.Services.AddHealthChecks()
        .AddSqlServer(connectionString!, name: "database", tags: ["db", "sql"])
        .AddCheck("self", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy(), tags: ["self"]);

    // Rate Limiting
    builder.Services.AddRateLimiter(options =>
    {
        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
            RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: context.User.Identity?.Name ?? context.Request.Headers.Host.ToString(),
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    AutoReplenishment = true,
                    PermitLimit = 100,
                    Window = TimeSpan.FromMinutes(1)
                }));

        options.OnRejected = async (context, token) =>
        {
            context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            await context.HttpContext.Response.WriteAsync("Too many requests. Please try again later.", token);
        };
    });

    // Services
    builder.Services.AddScoped<ILocalizationService, LocalizationService>();
    builder.Services.AddScoped<IAuthService, AuthService>();
    builder.Services.AddScoped<IUserService, UserService>();
    builder.Services.AddScoped<IAuditService, AuditService>();
    
    // Phase 3: Notification and Scheduling Services
    builder.Services.AddScoped<IEmailService, EmailService>();
    builder.Services.AddScoped<INotificationService, NotificationService>();
    builder.Services.AddScoped<IWebhookService, WebhookService>();
    builder.Services.AddScoped<IScheduleService, ScheduleService>();
    builder.Services.AddScoped<ScanJobProcessor>();

    // Domain & Infrastructure
    builder.Services.AddScoped(typeof(IRepository<>), typeof(EfRepository<>));
    builder.Services.AddSingleton<IScanEngine, ScanEngine>();
    builder.Services.AddSingleton<IHttpCrawler, HttpCrawler>();
    builder.Services.AddSingleton<IReportGenerator, ReportGenerator>();
    
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
    
    builder.Services.AddHttpClient();

    // Application (MediatR)
    builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(CreateScanCommand).Assembly));

    var app = builder.Build();

    // Seed default roles and admin user
    using (var scope = app.Services.CreateScope())
    {
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        
        // Create roles
        foreach (var roleName in Roles.All)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new ApplicationRole(roleName) 
                { 
                    IsSystemRole = true,
                    Description = roleName switch
                    {
                        Roles.Admin => "Full system access",
                        Roles.User => "Standard user access",
                        Roles.Viewer => "Read-only access",
                        _ => null
                    }
                });
                Log.Information("Created role: {Role}", roleName);
            }
        }

        // Create default admin user
        var adminEmail = "admin@raqeeb.io";
        if (await userManager.FindByEmailAsync(adminEmail) == null)
        {
            var adminUser = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                FirstName = "System",
                LastName = "Administrator",
                EmailConfirmed = true,
                IsActive = true
            };

            var result = await userManager.CreateAsync(adminUser, "Admin@123");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(adminUser, Roles.Admin);
                Log.Information("Created default admin user: {Email}", adminEmail);
            }
        }
    }

    // Configure the HTTP request pipeline.
    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Error", createScopeForErrors: true);
        app.UseHsts();
    }

    // Security headers
    app.Use(async (context, next) =>
    {
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        await next();
    });

    app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
    app.UseHttpsRedirection();

    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseAuthorization();

    // Health check endpoints
    app.MapHealthChecks("/health", new HealthCheckOptions
    {
        ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
    });

    app.MapHealthChecks("/health/ready", new HealthCheckOptions
    {
        Predicate = check => check.Tags.Contains("db"),
        ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
    });

    app.MapHealthChecks("/health/live", new HealthCheckOptions
    {
        Predicate = check => check.Tags.Contains("self"),
        ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
    });

    app.UseAntiforgery();
    
    // Hangfire Dashboard (protected by authorization)
    app.UseHangfireDashboard("/hangfire", new DashboardOptions
    {
        Authorization = new[] { new HangfireAuthorizationFilter() }
    });

    // Map auth endpoints (for login/logout via HTTP POST)
    app.MapAuthEndpoints();
    app.MapReportEndpoints();

    app.MapStaticAssets();
    app.MapRazorComponents<App>()
        .AddInteractiveServerRenderMode();

    Log.Information("Application started successfully");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
