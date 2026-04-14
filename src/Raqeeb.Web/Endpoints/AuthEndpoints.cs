using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Raqeeb.Domain.Entities;

namespace Raqeeb.Web.Endpoints;

/// <summary>
/// Authentication endpoints for login/logout operations.
/// These use traditional HTTP POST because SignInManager doesn't work with Blazor Server interactive mode.
/// </summary>
public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        app.MapPost("/api/auth/login", async (
            [FromForm] string email,
            [FromForm] string password,
            [FromForm] bool? rememberMe,
            [FromQuery] string? returnUrl,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            HttpContext httpContext) =>
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null || !user.IsActive)
            {
                return Results.Redirect($"/login?error=invalid");
            }

            var result = await signInManager.PasswordSignInAsync(user, password, rememberMe ?? false, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                user.LastLoginAt = DateTime.UtcNow;
                await userManager.UpdateAsync(user);
                return Results.Redirect(returnUrl ?? "/");
            }

            if (result.IsLockedOut)
            {
                return Results.Redirect("/login?error=locked");
            }

            return Results.Redirect("/login?error=invalid");
        }).DisableAntiforgery();

        app.MapPost("/api/auth/register", async (
            [FromForm] string email,
            [FromForm] string password,
            [FromForm] string firstName,
            [FromForm] string lastName,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager) =>
        {
            var existingUser = await userManager.FindByEmailAsync(email);
            if (existingUser != null)
            {
                return Results.Redirect("/register?error=exists");
            }

            var user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                FirstName = firstName,
                LastName = lastName,
                EmailConfirmed = true,
                IsActive = true
            };

            var result = await userManager.CreateAsync(user, password);

            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(user, Raqeeb.Domain.Constants.Roles.User);
                await signInManager.SignInAsync(user, isPersistent: true);
                return Results.Redirect("/");
            }

            return Results.Redirect("/register?error=failed");
        }).DisableAntiforgery();

        app.MapGet("/api/auth/logout", async (
            SignInManager<ApplicationUser> signInManager) =>
        {
            await signInManager.SignOutAsync();
            return Results.Redirect("/login");
        });
    }
}
