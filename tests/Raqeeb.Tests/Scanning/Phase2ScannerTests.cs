using FluentAssertions;
using Moq;
using Moq.Protected;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Scanning;
using Raqeeb.Infrastructure.Scanning.Modules;
using System.Net;

namespace Raqeeb.Tests.Scanning;

public class Phase2ScannerTests
{
    [Fact]
    public void XssScanner_ShouldHaveCorrectName()
    {
        var scanner = new XssScanner();
        scanner.Name.Should().Be("XssScanner");
    }

    [Fact]
    public void XssScanner_ShouldHaveDescription()
    {
        var scanner = new XssScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void SqlInjectionScanner_ShouldHaveCorrectName()
    {
        var scanner = new SqlInjectionScanner();
        scanner.Name.Should().Be("SqlInjectionScanner");
    }

    [Fact]
    public void SqlInjectionScanner_ShouldHaveDescription()
    {
        var scanner = new SqlInjectionScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void CsrfScanner_ShouldHaveCorrectName()
    {
        var scanner = new CsrfScanner();
        scanner.Name.Should().Be("CsrfScanner");
    }

    [Fact]
    public void CsrfScanner_ShouldHaveDescription()
    {
        var scanner = new CsrfScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task CsrfScanner_ShouldRunWithoutError()
    {
        var scanner = new CsrfScanner();
        var html = @"<html><body><form method=""post"" action=""/submit""><input name=""username"" /></form></body></html>";
        var context = CreateContextWithContent("https://example.com", html);
        
        var results = await scanner.ScanAsync(context);
        
        // Just verify it runs without exception
        results.Should().NotBeNull();
    }

    [Fact]
    public void SslTlsScanner_ShouldHaveCorrectName()
    {
        var scanner = new SslTlsScanner();
        scanner.Name.Should().Be("SslTlsScanner");
    }

    [Fact]
    public void SslTlsScanner_ShouldHaveDescription()
    {
        var scanner = new SslTlsScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task SslTlsScanner_ShouldDetectHttpUrl()
    {
        var scanner = new SslTlsScanner();
        var context = CreateContext("http://example.com", "");
        
        var results = await scanner.ScanAsync(context);
        
        results.Should().Contain(v => v.Name == "No HTTPS");
    }

    [Fact]
    public void CorsScanner_ShouldHaveCorrectName()
    {
        var scanner = new CorsScanner();
        scanner.Name.Should().Be("CorsScanner");
    }

    [Fact]
    public void CorsScanner_ShouldHaveDescription()
    {
        var scanner = new CorsScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void OpenRedirectScanner_ShouldHaveCorrectName()
    {
        var scanner = new OpenRedirectScanner();
        scanner.Name.Should().Be("OpenRedirectScanner");
    }

    [Fact]
    public void OpenRedirectScanner_ShouldHaveDescription()
    {
        var scanner = new OpenRedirectScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ClickjackingScanner_ShouldHaveCorrectName()
    {
        var scanner = new ClickjackingScanner();
        scanner.Name.Should().Be("ClickjackingScanner");
    }

    [Fact]
    public void ClickjackingScanner_ShouldHaveDescription()
    {
        var scanner = new ClickjackingScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ClickjackingScanner_ShouldDetectMissingXFrameOptions()
    {
        var scanner = new ClickjackingScanner();
        var context = CreateContext("https://example.com", "<html></html>");
        
        var results = await scanner.ScanAsync(context);
        
        results.Should().Contain(v => v.Name.Contains("X-Frame-Options") || v.Name.Contains("Frame Protection"));
    }

    [Fact]
    public void DirectoryBruteforceScanner_ShouldHaveCorrectName()
    {
        var scanner = new DirectoryBruteforceScanner();
        scanner.Name.Should().Be("DirectoryBruteforceScanner");
    }

    [Fact]
    public void DirectoryBruteforceScanner_ShouldHaveDescription()
    {
        var scanner = new DirectoryBruteforceScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void PortScanner_ShouldHaveCorrectName()
    {
        var scanner = new PortScanner();
        scanner.Name.Should().Be("PortScanner");
    }

    [Fact]
    public void PortScanner_ShouldHaveDescription()
    {
        var scanner = new PortScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void SubdomainEnumerationScanner_ShouldHaveCorrectName()
    {
        var scanner = new SubdomainEnumerationScanner();
        scanner.Name.Should().Be("SubdomainEnumerationScanner");
    }

    [Fact]
    public void SubdomainEnumerationScanner_ShouldHaveDescription()
    {
        var scanner = new SubdomainEnumerationScanner();
        scanner.Description.Should().NotBeNullOrEmpty();
    }

    private static ScanContext CreateContext(string url, string htmlContent)
    {
        var target = new Target { Id = Guid.NewGuid(), Url = url, IsVerified = true };
        var profile = new ScanProfile { Id = Guid.NewGuid(), Name = "Test" };
        var mockHandler = new Mock<HttpMessageHandler>();
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(htmlContent)
        };
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);
        return new ScanContext(target, profile, new HttpClient(mockHandler.Object));
    }

    private static ScanContext CreateContextWithContent(string url, string htmlContent)
    {
        var target = new Target { Id = Guid.NewGuid(), Url = url, IsVerified = true };
        var profile = new ScanProfile { Id = Guid.NewGuid(), Name = "Test" };
        var mockHandler = new Mock<HttpMessageHandler>();
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Content = new StringContent(htmlContent, System.Text.Encoding.UTF8, "text/html");
        
        mockHandler.Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);
        return new ScanContext(target, profile, new HttpClient(mockHandler.Object));
    }
}
