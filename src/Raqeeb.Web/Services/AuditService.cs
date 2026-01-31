using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Web.Services;

/// <summary>
/// Service for recording audit log entries.
/// </summary>
public interface IAuditService
{
    Task LogAsync(string action, string description, string? entityType = null, string? entityId = null, object? oldValues = null, object? newValues = null);
    Task LogLoginAsync(Guid userId, string userName, bool success, string? failureReason = null);
    Task LogScanEventAsync(Guid scanId, string action, string description);
}

public class AuditService : IAuditService
{
    private readonly IRepository<AuditLog> _auditRepository;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuditService> _logger;

    public AuditService(
        IRepository<AuditLog> auditRepository,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuditService> logger)
    {
        _auditRepository = auditRepository;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task LogAsync(
        string action, 
        string description, 
        string? entityType = null, 
        string? entityId = null, 
        object? oldValues = null, 
        object? newValues = null)
    {
        try
        {
            var context = _httpContextAccessor.HttpContext;
            var userId = GetCurrentUserId();
            var userName = GetCurrentUserName();

            var auditLog = new AuditLog
            {
                UserId = userId,
                UserName = userName,
                Action = action,
                Description = description,
                EntityType = entityType,
                EntityId = entityId,
                OldValues = oldValues != null ? JsonSerializer.Serialize(oldValues) : null,
                NewValues = newValues != null ? JsonSerializer.Serialize(newValues) : null,
                IpAddress = GetClientIpAddress(),
                UserAgent = context?.Request.Headers["User-Agent"].ToString(),
                Timestamp = DateTime.UtcNow
            };

            await _auditRepository.AddAsync(auditLog);

            _logger.LogInformation(
                "Audit: {Action} by {UserName} ({UserId}) - {Description}",
                action, userName ?? "Anonymous", userId, description);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create audit log entry");
        }
    }

    public async Task LogLoginAsync(Guid userId, string userName, bool success, string? failureReason = null)
    {
        var action = success ? AuditActions.Login : AuditActions.LoginFailed;
        var description = success 
            ? $"User {userName} logged in successfully" 
            : $"Login failed for {userName}: {failureReason}";

        var auditLog = new AuditLog
        {
            UserId = success ? userId : null,
            UserName = userName,
            Action = action,
            Description = description,
            IpAddress = GetClientIpAddress(),
            UserAgent = _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"].ToString(),
            Timestamp = DateTime.UtcNow
        };

        await _auditRepository.AddAsync(auditLog);

        if (success)
        {
            _logger.LogInformation("User {UserName} logged in from {IpAddress}", userName, auditLog.IpAddress);
        }
        else
        {
            _logger.LogWarning("Failed login attempt for {UserName} from {IpAddress}: {Reason}", 
                userName, auditLog.IpAddress, failureReason);
        }
    }

    public async Task LogScanEventAsync(Guid scanId, string action, string description)
    {
        await LogAsync(action, description, entityType: "ScanJob", entityId: scanId.ToString());
    }

    private Guid? GetCurrentUserId()
    {
        var userIdClaim = _httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(userIdClaim, out var userId) ? userId : null;
    }

    private string? GetCurrentUserName()
    {
        return _httpContextAccessor.HttpContext?.User.Identity?.Name;
    }

    private string? GetClientIpAddress()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null) return null;

        // Check for forwarded headers (when behind proxy/load balancer)
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',').First().Trim();
        }

        return context.Connection.RemoteIpAddress?.ToString();
    }
}
