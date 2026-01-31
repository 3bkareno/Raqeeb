using Microsoft.AspNetCore.Identity;

namespace Raqeeb.Domain.Entities;

/// <summary>
/// Application user entity extending ASP.NET Identity.
/// </summary>
public class ApplicationUser : IdentityUser<Guid>
{
    /// <summary>
    /// User's first name.
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// User's last name.
    /// </summary>
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// User's full name.
    /// </summary>
    public string FullName => $"{FirstName} {LastName}".Trim();

    /// <summary>
    /// User's preferred language (en, ar).
    /// </summary>
    public string PreferredLanguage { get; set; } = "en";

    /// <summary>
    /// User's preferred theme (light, dark).
    /// </summary>
    public string PreferredTheme { get; set; } = "light";

    /// <summary>
    /// URL to user's profile picture.
    /// </summary>
    public string? ProfilePictureUrl { get; set; }

    /// <summary>
    /// Date when the user was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Date when the user was last updated.
    /// </summary>
    public DateTime? UpdatedAt { get; set; }

    /// <summary>
    /// Date when the user last logged in.
    /// </summary>
    public DateTime? LastLoginAt { get; set; }

    /// <summary>
    /// Whether the user account is active.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Organization/company the user belongs to (for future multi-tenancy).
    /// </summary>
    public Guid? OrganizationId { get; set; }

    /// <summary>
    /// Notification preferences - receive scan completion emails.
    /// </summary>
    public bool NotifyScanComplete { get; set; } = true;

    /// <summary>
    /// Notification preferences - receive critical vulnerability alerts.
    /// </summary>
    public bool NotifyCriticalVulnerabilities { get; set; } = true;

    /// <summary>
    /// Targets owned by this user.
    /// </summary>
    public virtual ICollection<Target> Targets { get; set; } = new List<Target>();
}

/// <summary>
/// Application role entity extending ASP.NET Identity.
/// </summary>
public class ApplicationRole : IdentityRole<Guid>
{
    /// <summary>
    /// Description of the role.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Date when the role was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Whether this is a system role (cannot be deleted).
    /// </summary>
    public bool IsSystemRole { get; set; }

    public ApplicationRole() : base() { }

    public ApplicationRole(string roleName) : base(roleName)
    {
        Id = Guid.NewGuid();
    }
}
