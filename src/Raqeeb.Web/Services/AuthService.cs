using Microsoft.AspNetCore.Identity;
using Raqeeb.Domain.Entities;

namespace Raqeeb.Web.Services;

/// <summary>
/// Authentication service for handling user login/register.
/// </summary>
public interface IAuthService
{
    Task<AuthResult> LoginAsync(string email, string password);
    Task<AuthResult> RegisterAsync(string email, string password, string firstName, string lastName);
    Task LogoutAsync();
    Task<ApplicationUser?> GetCurrentUserAsync();
}

/// <summary>
/// Result of an authentication operation.
/// </summary>
public record AuthResult(bool Succeeded, string? ErrorMessage = null, ApplicationUser? User = null);

/// <summary>
/// Implementation of authentication service using ASP.NET Identity.
/// </summary>
public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IAuditService _auditService;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IAuditService auditService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _auditService = auditService;
    }

    public async Task<AuthResult> LoginAsync(string email, string password)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            await _auditService.LogLoginAsync(Guid.Empty, email, false, "User not found");
            return new AuthResult(false, "Invalid email or password.");
        }

        if (!user.IsActive)
        {
            await _auditService.LogLoginAsync(user.Id, email, false, "Account disabled");
            return new AuthResult(false, "Your account has been disabled.");
        }

        var result = await _signInManager.PasswordSignInAsync(user, password, isPersistent: true, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            await _auditService.LogLoginAsync(user.Id, email, true);
            return new AuthResult(true, User: user);
        }

        if (result.IsLockedOut)
        {
            await _auditService.LogLoginAsync(user.Id, email, false, "Account locked out");
            return new AuthResult(false, "Account is locked. Please try again later.");
        }

        if (result.RequiresTwoFactor)
        {
            return new AuthResult(false, "Two-factor authentication required.");
        }

        await _auditService.LogLoginAsync(user.Id, email, false, "Invalid password");
        return new AuthResult(false, "Invalid email or password.");
    }

    public async Task<AuthResult> RegisterAsync(string email, string password, string firstName, string lastName)
    {
        var existingUser = await _userManager.FindByEmailAsync(email);
        if (existingUser != null)
        {
            return new AuthResult(false, "An account with this email already exists.");
        }

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = firstName,
            LastName = lastName,
            EmailConfirmed = true, // For demo; in production, require email confirmation
            IsActive = true
        };

        var result = await _userManager.CreateAsync(user, password);

        if (result.Succeeded)
        {
            // Assign default role
            await _userManager.AddToRoleAsync(user, Domain.Constants.Roles.User);
            await _signInManager.SignInAsync(user, isPersistent: true);
            await _auditService.LogAsync(AuditActions.Create, $"New user registered: {email}", "User", user.Id.ToString());
            return new AuthResult(true, User: user);
        }

        var errors = string.Join(" ", result.Errors.Select(e => e.Description));
        return new AuthResult(false, errors);
    }

    public async Task LogoutAsync()
    {
        var httpContext = _signInManager.Context;
        var userName = httpContext?.User?.Identity?.Name ?? "Unknown";
        await _auditService.LogAsync(AuditActions.Logout, $"User {userName} logged out");
        await _signInManager.SignOutAsync();
    }

    public async Task<ApplicationUser?> GetCurrentUserAsync()
    {
        // This will be implemented when we have proper authentication state
        return await Task.FromResult<ApplicationUser?>(null);
    }
}
