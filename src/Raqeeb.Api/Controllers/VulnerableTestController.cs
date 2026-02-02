using Microsoft.AspNetCore.Mvc;

namespace Raqeeb.Api.Controllers;

/// <summary>
/// Test endpoints that intentionally have security vulnerabilities for scanner validation.
/// WARNING: These endpoints should NEVER be deployed to production.
/// </summary>
[ApiController]
[Route("api/test/vulnerable")]
[ApiExplorerSettings(IgnoreApi = true)] // Hide from Swagger in production
public class VulnerableTestController : ControllerBase
{
    /// <summary>
    /// Endpoint with no security headers.
    /// </summary>
    [HttpGet("no-headers")]
    public IActionResult NoSecurityHeaders()
    {
        // Remove all security headers
        Response.Headers.Remove("X-Frame-Options");
        Response.Headers.Remove("X-Content-Type-Options");
        Response.Headers.Remove("Content-Security-Policy");
        
        return Ok(new { message = "This endpoint has no security headers" });
    }

    /// <summary>
    /// Endpoint with weak CSP.
    /// </summary>
    [HttpGet("weak-csp")]
    public IActionResult WeakContentSecurityPolicy()
    {
        Response.Headers["Content-Security-Policy"] = "default-src *";
        return Ok(new { message = "This endpoint has weak CSP" });
    }

    /// <summary>
    /// Endpoint that exposes server version.
    /// </summary>
    [HttpGet("server-disclosure")]
    public IActionResult ServerVersionDisclosure()
    {
        Response.Headers["Server"] = "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f";
        return Ok(new { message = "Server version exposed" });
    }

    /// <summary>
    /// Endpoint with XSS Protection disabled.
    /// </summary>
    [HttpGet("xss-disabled")]
    public IActionResult XSSProtectionDisabled()
    {
        Response.Headers["X-XSS-Protection"] = "0";
        return Ok(new { message = "XSS Protection is disabled" });
    }

    /// <summary>
    /// Endpoint that reflects user input (XSS vulnerable).
    /// </summary>
    [HttpGet("reflected-xss")]
    public IActionResult ReflectedXSS([FromQuery] string name)
    {
        // Intentionally vulnerable to XSS
        return Content($"<html><body>Hello {name}</body></html>", "text/html");
    }

    /// <summary>
    /// Endpoint vulnerable to SQL injection (simulated).
    /// </summary>
    [HttpGet("sql-injection")]
    public IActionResult SQLInjection([FromQuery] string id)
    {
        // Simulate SQL injection vulnerability
        var query = $"SELECT * FROM users WHERE id = {id}";
        return Ok(new { query, warning = "This query is vulnerable to SQL injection" });
    }

    /// <summary>
    /// Endpoint with missing CORS headers.
    /// </summary>
    [HttpGet("missing-cors")]
    public IActionResult MissingCORS()
    {
        return Ok(new { message = "No CORS headers set" });
    }

    /// <summary>
    /// Endpoint with overly permissive CORS.
    /// </summary>
    [HttpGet("permissive-cors")]
    public IActionResult PermissiveCORS()
    {
        Response.Headers["Access-Control-Allow-Origin"] = "*";
        Response.Headers["Access-Control-Allow-Methods"] = "*";
        Response.Headers["Access-Control-Allow-Headers"] = "*";
        return Ok(new { message = "CORS allows everything" });
    }

    /// <summary>
    /// Endpoint that returns sensitive data without authentication.
    /// </summary>
    [HttpGet("sensitive-data")]
    public IActionResult SensitiveDataExposure()
    {
        return Ok(new
        {
            users = new[]
            {
                new { id = 1, email = "admin@example.com", password_hash = "5f4dcc3b5aa765d61d8327deb882cf99" },
                new { id = 2, email = "user@example.com", password_hash = "098f6bcd4621d373cade4e832627b4f6" }
            }
        });
    }

    /// <summary>
    /// Endpoint with clickjacking vulnerability (no X-Frame-Options).
    /// </summary>
    [HttpGet("clickjacking")]
    public IActionResult Clickjacking()
    {
        Response.Headers.Remove("X-Frame-Options");
        return Content("<html><body><h1>This page can be embedded in iframes</h1></body></html>", "text/html");
    }

    /// <summary>
    /// Secure endpoint for comparison (all headers set correctly).
    /// </summary>
    [HttpGet("secure")]
    public IActionResult SecureEndpoint()
    {
        Response.Headers["X-Frame-Options"] = "DENY";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Content-Security-Policy"] = "default-src 'self'";
        Response.Headers["X-XSS-Protection"] = "1; mode=block";
        Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
        Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        
        return Ok(new { message = "This endpoint has all security headers" });
    }
}
