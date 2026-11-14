namespace MaintenX.IntegrationTests;

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using MaintenX.Api.Common.Modules;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

public class SecurityConfigurationIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _baseFactory;

    private const string ActiveKeyId = "test-active-key-v1";
    private const string RetiredKeyId = "test-retired-key-v0";
    private static readonly string ActiveSigningKeyBase64 = GenerateBase64Key(32);
    private static readonly string RetiredSigningKeyBase64 = GenerateBase64Key(32);
    private const string TestIssuer = "https://api.maintenx.internal";
    private const string TestAudience = "https://maintenx.internal";

    private static string GenerateBase64Key(int byteCount = 32)
    {
        var bytes = new byte[byteCount];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }

    public SecurityConfigurationIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _baseFactory = factory;
    }

    private WebApplicationFactory<Program> CreateConfiguredFactory(
        string? activeKey = null,
        string? keyId = null,
        Dictionary<string, string>? verificationKeys = null,
        List<string>? knownProxies = null,
        string environment = "Development",
        bool overrideJwtSettings = true)
    {
        return _baseFactory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(environment);
            builder.UseSetting("ConnectionStrings:DefaultConnection", "Host=localhost;Database=test;Username=test;Password=test;");

            if (overrideJwtSettings)
            {
                builder.UseSetting("Jwt:Issuer", TestIssuer);
                builder.UseSetting("Jwt:Audience", TestAudience);
                builder.UseSetting("Jwt:KeyId", keyId ?? ActiveKeyId);
                builder.UseSetting("Jwt:SigningKey", activeKey ?? ActiveSigningKeyBase64);
                builder.UseSetting("Jwt:AccessTokenLifetimeMinutes", "15");
                builder.UseSetting("Jwt:RetiredKeyRetentionHours", "24");
            }

            if (verificationKeys != null)
            {
                foreach (var (k, v) in verificationKeys)
                {
                    builder.UseSetting($"Jwt:VerificationKeys:{k}", v);
                }
            }

            if (knownProxies != null)
            {
                for (int i = 0; i < knownProxies.Count; i++)
                {
                    builder.UseSetting($"TrustedProxies:KnownProxies:{i}", knownProxies[i]);
                }
            }

            builder.ConfigureAppConfiguration((_, config) =>
            {
                var settings = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:DefaultConnection"] = "Host=localhost;Database=test;Username=test;Password=test;"
                };

                if (overrideJwtSettings)
                {
                    settings["Jwt:Issuer"] = TestIssuer;
                    settings["Jwt:Audience"] = TestAudience;
                    settings["Jwt:KeyId"] = keyId ?? ActiveKeyId;
                    settings["Jwt:SigningKey"] = activeKey ?? ActiveSigningKeyBase64;
                    settings["Jwt:AccessTokenLifetimeMinutes"] = "15";
                    settings["Jwt:RetiredKeyRetentionHours"] = "24";
                }

                if (verificationKeys != null)
                {
                    foreach (var (k, v) in verificationKeys)
                    {
                        settings[$"Jwt:VerificationKeys:{k}"] = v;
                    }
                }

                if (knownProxies != null)
                {
                    for (int i = 0; i < knownProxies.Count; i++)
                    {
                        settings[$"TrustedProxies:KnownProxies:{i}"] = knownProxies[i];
                    }
                }

                config.AddInMemoryCollection(settings);
            });

            builder.ConfigureServices(services =>
            {
                // Register startup filter to simulate physical socket RemoteIpAddress in TestServer
                services.AddTransient<IStartupFilter, TestSocketSimulationStartupFilter>();

                // Register test security module implementing IModule
                services.AddSingleton<IModule, TestSecurityModule>();
            });
        });
    }

    private static string GenerateJwt(
        string signingKeyBase64,
        string? kid,
        string issuer = TestIssuer,
        string audience = TestAudience,
        TimeSpan? lifetime = null,
        string algorithm = SecurityAlgorithms.HmacSha256,
        string subject = "user-123")
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var keyBytes = Convert.FromBase64String(signingKeyBase64);
        var securityKey = new SymmetricSecurityKey(keyBytes);

        if (!string.IsNullOrEmpty(kid))
        {
            securityKey.KeyId = kid;
        }

        var creds = new SigningCredentials(securityKey, algorithm);

        var expires = DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(15));
        var notBefore = DateTime.UtcNow.AddMinutes(-1);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, subject)]),
            Issuer = issuer,
            Audience = audience,
            NotBefore = notBefore,
            Expires = expires,
            SigningCredentials = creds
        };

        var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
        if (kid == null)
        {
            token.Header.Remove("kid");
        }

        return tokenHandler.WriteToken(token);
    }

    [Fact]
    public async Task JwtAuthentication_WithValidTokenAndActiveKid_AuthenticatesSuccessfully()
    {
        var factory = CreateConfiguredFactory();
        var client = factory.CreateClient();

        var token = GenerateJwt(ActiveSigningKeyBase64, ActiveKeyId);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/test-security/protected");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task JwtAuthentication_WithRetiredKeyInVerificationRing_AuthenticatesSuccessfully()
    {
        var verificationKeys = new Dictionary<string, string>
        {
            [RetiredKeyId] = RetiredSigningKeyBase64
        };

        var factory = CreateConfiguredFactory(verificationKeys: verificationKeys);
        var client = factory.CreateClient();

        var token = GenerateJwt(RetiredSigningKeyBase64, RetiredKeyId);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/test-security/protected");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task JwtAuthentication_WithUnknownKid_RejectsWith401Unauthorized()
    {
        var factory = CreateConfiguredFactory();
        var client = factory.CreateClient();

        var unknownKey = GenerateBase64Key(32);
        var token = GenerateJwt(unknownKey, "completely-unknown-kid");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/test-security/protected");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var content = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(content);
        Assert.Equal(401, json.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task JwtAuthentication_WithMissingKidHeader_RejectsWith401Unauthorized()
    {
        var factory = CreateConfiguredFactory();
        var client = factory.CreateClient();

        var token = GenerateJwt(ActiveSigningKeyBase64, kid: null);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/test-security/protected");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task JwtAuthentication_WithUnsupportedAlgorithm_RejectsWith401Unauthorized()
    {
        var factory = CreateConfiguredFactory();
        var client = factory.CreateClient();

        var sha512Key = GenerateBase64Key(64);
        var token = GenerateJwt(sha512Key, ActiveKeyId, algorithm: SecurityAlgorithms.HmacSha512);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/test-security/protected");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task JwtAuthentication_WithExpiredToken_ZeroClockSkew_RejectsImmediatelyWith401()
    {
        var factory = CreateConfiguredFactory();
        var client = factory.CreateClient();

        var token = GenerateJwt(ActiveSigningKeyBase64, ActiveKeyId, lifetime: TimeSpan.FromSeconds(-5));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/test-security/protected");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TrustedProxy_WhenForwardedHeadersSentFromUntrustedProxy_DoesNotSpoofClientIp()
    {
        // Proxy 10.0.0.1 is trusted. Client connects from 192.168.1.100 (untrusted socket)
        var factory = CreateConfiguredFactory(knownProxies: ["10.0.0.1"]);
        var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", "192.168.1.100");
        client.DefaultRequestHeaders.Add("X-Forwarded-For", "203.0.113.195");
        client.DefaultRequestHeaders.Add("X-Forwarded-Proto", "https");

        var response = await client.GetAsync("/test-security/client-ip");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(content);
        var resolvedIp = json.RootElement.GetProperty("ip").GetString();

        // Must reject spoofed header; resolved IP must remain 192.168.1.100
        Assert.Equal("192.168.1.100", resolvedIp);
        Assert.NotEqual("203.0.113.195", resolvedIp);
    }

    [Fact]
    public async Task TrustedProxy_WhenForwardedHeadersSentFromTrustedProxy_ResolvesClientIpCorrectly()
    {
        // 10.0.0.1 is trusted. Client connects from 10.0.0.1 (trusted proxy)
        var factory = CreateConfiguredFactory(knownProxies: ["10.0.0.1"]);
        var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", "10.0.0.1");
        client.DefaultRequestHeaders.Add("X-Forwarded-For", "198.51.100.42");
        client.DefaultRequestHeaders.Add("X-Forwarded-Proto", "https");

        var response = await client.GetAsync("/test-security/client-ip");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(content);
        var resolvedIp = json.RootElement.GetProperty("ip").GetString();

        // Header accepted; resolved IP updated to client's forwarded IP
        Assert.Equal("198.51.100.42", resolvedIp);
    }

    [Fact]
    public async Task RateLimiting_RegistrationPolicy_ThrottlesAfter5RequestsPerMinute_AndReturns429WithProblemDetails()
    {
        var factory = CreateConfiguredFactory();
        var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", "192.0.2.10");

        for (int i = 0; i < 5; i++)
        {
            var okResponse = await client.GetAsync("/test-security/rate-limit-registration");
            Assert.Equal(HttpStatusCode.OK, okResponse.StatusCode);
        }

        // 6th request must be throttled
        var throttledResponse = await client.GetAsync("/test-security/rate-limit-registration");
        Assert.Equal(HttpStatusCode.TooManyRequests, throttledResponse.StatusCode);
        Assert.Equal("application/problem+json", throttledResponse.Content.Headers.ContentType?.MediaType);
        Assert.True(throttledResponse.Headers.Contains("Retry-After"));

        var problemJson = await throttledResponse.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(problemJson);
        Assert.Equal(429, doc.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("Too Many Requests", doc.RootElement.GetProperty("title").GetString());
    }

    [Fact]
    public async Task RateLimiting_LoginPolicy_ThrottlesAfter10RequestsPerMinute_AndReturns429WithRetryAfter()
    {
        var factory = CreateConfiguredFactory();
        var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", "192.0.2.20");

        for (int i = 0; i < 10; i++)
        {
            var okResponse = await client.GetAsync("/test-security/rate-limit-login");
            Assert.Equal(HttpStatusCode.OK, okResponse.StatusCode);
        }

        var throttledResponse = await client.GetAsync("/test-security/rate-limit-login");
        Assert.Equal(HttpStatusCode.TooManyRequests, throttledResponse.StatusCode);
        Assert.True(throttledResponse.Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task RateLimiting_RefreshPolicy_ThrottlesAfter30RequestsPerMinute_AndReturns429()
    {
        var factory = CreateConfiguredFactory();
        var client = factory.CreateClient();

        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", "192.0.2.30");

        for (int i = 0; i < 30; i++)
        {
            var okResponse = await client.GetAsync("/test-security/rate-limit-refresh");
            Assert.Equal(HttpStatusCode.OK, okResponse.StatusCode);
        }

        var throttledResponse = await client.GetAsync("/test-security/rate-limit-refresh");
        Assert.Equal(HttpStatusCode.TooManyRequests, throttledResponse.StatusCode);
    }

    [Fact]
    public async Task RateLimiting_MissingClientIp_RestrictsUnidentifiedClientToConstrainedPartition()
    {
        var factory = CreateConfiguredFactory();
        var client = factory.CreateClient();

        // No X-Test-Socket-Remote-Ip provided: RemoteIpAddress is null
        var firstResponse = await client.GetAsync("/test-security/rate-limit-registration");
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);

        // 2nd request from missing IP should immediately be throttled (constrained 1-permit partition)
        var secondResponse = await client.GetAsync("/test-security/rate-limit-registration");
        Assert.Equal(HttpStatusCode.TooManyRequests, secondResponse.StatusCode);
    }

    [Fact]
    public void ProductionStartup_WhenTrustedProxyAllowlistIsMissing_ThrowsValidationException()
    {
        var factory = CreateConfiguredFactory(knownProxies: [], environment: "Production");

        var ex = Assert.Throws<OptionsValidationException>(() =>
        {
            _ = factory.CreateClient();
        });

        Assert.Contains("Production security violation", ex.Message);
    }

    [Fact]
    public void ProductionStartup_WhenJwtSigningKeyIsMissing_ThrowsValidationException()
    {
        var factory = CreateConfiguredFactory(activeKey: "", knownProxies: ["10.0.0.1"], environment: "Production");

        var ex = Assert.Throws<OptionsValidationException>(() =>
        {
            _ = factory.CreateClient();
        });

        Assert.Contains("Jwt:SigningKey", ex.Message);
    }

    [Fact]
    public void ProductionStartup_WhenJwtSigningKeyHasInsufficientEntropy_ThrowsValidationException()
    {
        var shortKey = GenerateBase64Key(16); // 128 bits
        var factory = CreateConfiguredFactory(activeKey: shortKey, knownProxies: ["10.0.0.1"], environment: "Production");

        var ex = Assert.Throws<OptionsValidationException>(() =>
        {
            _ = factory.CreateClient();
        });

        Assert.Contains("Insufficient key entropy", ex.Message);
    }

    [Fact]
    public async Task DevelopmentStartup_WithDevelopmentSettings_SucceedsWithoutCustomKeyOverrides()
    {
        var factory = CreateConfiguredFactory(overrideJwtSettings: false, environment: "Development");
        var client = factory.CreateClient();

        var response = await client.GetAsync("/health/live");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task JwtAuthentication_WhenRetiredKeyPurgedAfterRetentionWindow_RejectsWith401Unauthorized()
    {
        var factory = CreateConfiguredFactory(verificationKeys: []);
        var client = factory.CreateClient();

        var token = GenerateJwt(RetiredSigningKeyBase64, RetiredKeyId);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync("/test-security/protected");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    private sealed class TestSocketSimulationStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                // Must run before UseForwardedHeaders() to simulate the connecting TCP socket IP
                app.Use(async (context, nextMiddleware) =>
                {
                    if (context.Request.Headers.TryGetValue("X-Test-Socket-Remote-Ip", out var socketIpHeader) &&
                        IPAddress.TryParse(socketIpHeader.ToString(), out var socketIp))
                    {
                        context.Connection.RemoteIpAddress = socketIp;
                    }

                    await nextMiddleware();
                });

                next(app);
            };
        }
    }

    private sealed class TestSecurityModule : IModule
    {
        public IServiceCollection RegisterModule(IServiceCollection services, IConfiguration configuration) => services;

        public IEndpointRouteBuilder MapEndpoints(IEndpointRouteBuilder endpoints)
        {
            endpoints.MapGet("/test-security/protected", () => Results.Ok(new { status = "authorized" }))
                .RequireAuthorization();

            endpoints.MapGet("/test-security/client-ip", (HttpContext context) =>
            {
                var ip = context.Connection.RemoteIpAddress?.ToString() ?? "none";
                return Results.Ok(new { ip });
            });

            endpoints.MapGet("/test-security/rate-limit-registration", () => Results.Ok("registered"))
                .RequireRateLimiting(AuthRateLimitPolicies.Registration);

            endpoints.MapGet("/test-security/rate-limit-login", () => Results.Ok("logged-in"))
                .RequireRateLimiting(AuthRateLimitPolicies.Login);

            endpoints.MapGet("/test-security/rate-limit-refresh", () => Results.Ok("refreshed"))
                .RequireRateLimiting(AuthRateLimitPolicies.Refresh);

            return endpoints;
        }
    }
}
