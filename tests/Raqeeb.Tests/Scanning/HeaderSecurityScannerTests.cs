using FluentAssertions;
using Moq;
using Moq.Protected;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Scanning;
using Raqeeb.Infrastructure.Scanning.Modules;
using System.Net;

namespace Raqeeb.Tests.Scanning;

public class HeaderSecurityScannerTests
{
    private readonly HeaderSecurityScanner _scanner = new();

    [Fact]
    public void Name_ShouldBeHeaderSecurityScanner()
    {
        _scanner.Name.Should().Be("HeaderSecurityScanner");
    }

    [Fact]
    public void Description_ShouldNotBeEmpty()
    {
        _scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ScanAsync_WithMissingHeaders_ShouldDetectVulnerabilities()
    {
        var context = CreateContext("https://example.com", new Dictionary<string, string>());
        var results = await _scanner.ScanAsync(context);
        results.Should().NotBeEmpty();
        results.Should().Contain(v => v.Name == "Missing X-Content-Type-Options");
    }

    [Fact]
    public async Task ScanAsync_WithSecureHeaders_ShouldBeEmpty()
    {
        var headers = new Dictionary<string, string>
        {
            ["X-Content-Type-Options"] = "nosniff",
            ["Strict-Transport-Security"] = "max-age=31536000",
            ["X-Frame-Options"] = "DENY",
            ["X-XSS-Protection"] = "1; mode=block",
            ["Referrer-Policy"] = "strict-origin-when-cross-origin",
            ["Permissions-Policy"] = "geolocation=(), camera=()"
        };
        var context = CreateContext("https://example.com", headers, addCsp: true);
        var results = await _scanner.ScanAsync(context);
        results.Should().BeEmpty();
    }

    private static ScanContext CreateContext(string url, Dictionary<string, string> headers, bool addCsp = false)
    {
        var target = new Target { Id = Guid.NewGuid(), Url = url, IsVerified = true };
        var profile = new ScanProfile { Id = Guid.NewGuid(), Name = "Test" };
        var mockHandler = new Mock<HttpMessageHandler>();
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        foreach (var header in headers)
            response.Headers.TryAddWithoutValidation(header.Key, header.Value);
        if (addCsp)
            response.Content.Headers.TryAddWithoutValidation("Content-Security-Policy", "default-src 'self'");
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);
        return new ScanContext(target, profile, new HttpClient(mockHandler.Object));
    }
}
