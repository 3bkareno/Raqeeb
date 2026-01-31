namespace Raqeeb.Domain.Entities;

/// <summary>
/// Represents an audit log entry for tracking user actions.
/// </summary>
public class AuditLog
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// The user who performed the action.
    /// </summary>
    public Guid? UserId { get; set; }

    /// <summary>
    /// Username for display purposes.
    /// </summary>
    public string? UserName { get; set; }

    /// <summary>
    /// The type of action performed (Create, Update, Delete, Login, etc.).
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// The entity type affected (Target, ScanJob, User, etc.).
    /// </summary>
    public string? EntityType { get; set; }

    /// <summary>
    /// The ID of the affected entity.
    /// </summary>
    public string? EntityId { get; set; }

    /// <summary>
    /// Description of the action.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// The old values before the change (JSON serialized).
    /// </summary>
    public string? OldValues { get; set; }

    /// <summary>
    /// The new values after the change (JSON serialized).
    /// </summary>
    public string? NewValues { get; set; }

    /// <summary>
    /// IP address of the user.
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent string from the browser.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// When the action occurred.
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Navigation property to the user.
    /// </summary>
    public virtual ApplicationUser? User { get; set; }
}

/// <summary>
/// Common audit action types.
/// </summary>
public static class AuditActions
{
    public const string Login = "Login";
    public const string Logout = "Logout";
    public const string LoginFailed = "LoginFailed";
    public const string PasswordChanged = "PasswordChanged";
    public const string PasswordReset = "PasswordReset";
    
    public const string Create = "Create";
    public const string Update = "Update";
    public const string Delete = "Delete";
    public const string View = "View";
    
    public const string ScanStarted = "ScanStarted";
    public const string ScanCompleted = "ScanCompleted";
    public const string ScanFailed = "ScanFailed";
    public const string ScanCancelled = "ScanCancelled";
    
    public const string ReportExported = "ReportExported";
    public const string SettingsChanged = "SettingsChanged";
}
