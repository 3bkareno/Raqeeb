using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Raqeeb.Domain.Entities;

namespace Raqeeb.Web.Services;

/// <summary>
/// Service for accessing current user information in Blazor components.
/// </summary>
public interface IUserService
{
    Task<ApplicationUser?> GetCurrentUserAsync();
    Task<bool> IsAuthenticatedAsync();
    Task<bool> IsInRoleAsync(string role);
    Task<IList<string>> GetRolesAsync();
    Task<bool> HasPermissionAsync(string permission);
}

public class UserService : IUserService
{
    private readonly AuthenticationStateProvider _authStateProvider;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public UserService(
        AuthenticationStateProvider authStateProvider,
        UserManager<ApplicationUser> userManager,
        IHttpContextAccessor httpContextAccessor)
    {
        _authStateProvider = authStateProvider;
        _userManager = userManager;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<ApplicationUser?> GetCurrentUserAsync()
    {
        var authState = await _authStateProvider.GetAuthenticationStateAsync();
        var user = authState.User;

        if (user.Identity?.IsAuthenticated != true)
        {
            return null;
        }

        return await _userManager.GetUserAsync(user);
    }

    public async Task<bool> IsAuthenticatedAsync()
    {
        var authState = await _authStateProvider.GetAuthenticationStateAsync();
        return authState.User.Identity?.IsAuthenticated == true;
    }

    public async Task<bool> IsInRoleAsync(string role)
    {
        var user = await GetCurrentUserAsync();
        if (user == null) return false;
        
        return await _userManager.IsInRoleAsync(user, role);
    }

    public async Task<IList<string>> GetRolesAsync()
    {
        var user = await GetCurrentUserAsync();
        if (user == null) return [];
        
        return await _userManager.GetRolesAsync(user);
    }

    public async Task<bool> HasPermissionAsync(string permission)
    {
        var user = await GetCurrentUserAsync();
        if (user == null) return false;

        // Check if user has the permission claim
        var claims = await _userManager.GetClaimsAsync(user);
        if (claims.Any(c => c.Type == "Permission" && c.Value == permission))
        {
            return true;
        }

        // Check role-based permissions
        var roles = await _userManager.GetRolesAsync(user);
        
        // Admin has all permissions
        if (roles.Contains(Domain.Constants.Roles.Admin))
        {
            return true;
        }

        // Check permission mapping
        foreach (var role in roles)
        {
            var rolePermissions = GetPermissionsForRole(role);
            if (rolePermissions.Contains(permission))
            {
                return true;
            }
        }

        return false;
    }

    private static string[] GetPermissionsForRole(string role)
    {
        return role switch
        {
            Domain.Constants.Roles.Admin => Domain.Constants.Permissions.AdminPermissions,
            Domain.Constants.Roles.User => Domain.Constants.Permissions.UserPermissions,
            Domain.Constants.Roles.Viewer => Domain.Constants.Permissions.ViewerPermissions,
            _ => []
        };
    }
}
