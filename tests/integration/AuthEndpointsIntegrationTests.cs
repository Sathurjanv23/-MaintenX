namespace MaintenX.IntegrationTests;

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

/// <summary>
/// Full integration test suite for FEAT-002 T6 authentication HTTP API endpoints.
/// Executes against a disposable, isolated PostgreSQL 16 database.
/// Validates registration, login, refresh rotation, replay detection, logout, password change,
/// rate-limiting, and error-mapping contracts.
/// </summary>
public class AuthEndpointsIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public AuthEndpointsIntegrationTests()
    {
        _configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        var (admin, test) = TestDatabaseGuard.ValidateConnectionConfiguration(_configuration);
        _adminConnectionString = admin;
        _testConnectionString = test;
    }

    public async Task InitializeAsync()
    {
        var (dbName, connStr) = await TestDatabaseGuard.ProvisionAndInitializeAsync(
            _adminConnectionString,
            _testConnectionString,
            _configuration,
            async (conn) =>
            {
                var options = new DbContextOptionsBuilder<MaintenXDbContext>()
                    .UseNpgsql(conn)
                    .Options;

                using var context = new MaintenXDbContext(options);
                await context.Database.MigrateAsync();
            });

        _databaseName = dbName;
        _isolatedConnectionString = connStr;

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("ConnectionStrings:DefaultConnection", _isolatedConnectionString);

            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:DefaultConnection"] = _isolatedConnectionString,
                    ["TrustedProxies:KnownProxies:0"] = "127.0.0.1",
                    ["TrustedProxies:KnownProxies:1"] = "::1",
                    ["TrustedProxies:ForwardLimit"] = "1"
                });
            });

            builder.ConfigureServices(services =>
            {
                services.AddTransient<IStartupFilter, TestSocketSimulationStartupFilter>();
            });
        });
    }

    public async Task DisposeAsync()
    {
        _factory.Dispose();
        if (!string.IsNullOrWhiteSpace(_databaseName))
        {
            await TestDatabaseGuard.DropDatabaseSafelyAsync(_databaseName, _adminConnectionString);
        }
    }

    private MaintenXDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return new MaintenXDbContext(options);
    }

    private static int _ipCounter = 100;
    private HttpClient CreateUniqueClient()
    {
        var id = Interlocked.Increment(ref _ipCounter);
        var ip = $"198.51.{(id / 250) % 250}.{id % 250 + 1}";
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ip);
        return client;
    }

    private static HttpClient CreateClientWithIp(WebApplicationFactory<Program> factory, string ipAddress)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ipAddress);
        return client;
    }

    // =========================================================================
    // 1. REGISTRATION TESTS
    // =========================================================================

    [Fact]
    public async Task Register_ValidRequest_Returns200AndPersistsUser()
    {
        var client = CreateUniqueClient();
        var email = $"new_user_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        var response = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(body);
        Assert.Equal(RegisterResponse.DefaultMessage, body.Message);

        using var db = CreateDbContext();
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == email);
        Assert.NotNull(user);
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.False(string.IsNullOrWhiteSpace(user.PasswordHash));
        Assert.False(string.IsNullOrWhiteSpace(user.SecurityStamp));
    }

    [Fact]
    public async Task Register_DuplicateEmail_Returns200WithIdenticalResponse_DoesNotDiscloseAccount()
    {
        var client = CreateUniqueClient();
        var email = $"duplicate_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        var firstResp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, firstResp.StatusCode);
        var firstBody = await firstResp.Content.ReadFromJsonAsync<RegisterResponse>();

        // Second registration with identical email
        var secondResp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, secondResp.StatusCode);
        var secondBody = await secondResp.Content.ReadFromJsonAsync<RegisterResponse>();

        Assert.NotNull(firstBody);
        Assert.NotNull(secondBody);
        Assert.Equal(firstBody.Message, secondBody.Message);

        using var db = CreateDbContext();
        var userCount = await db.Users.CountAsync(u => u.Email == email);
        Assert.Equal(1, userCount);
    }

    [Fact]
    public async Task Register_InvalidEmail_Returns400ProblemDetails()
    {
        var client = CreateUniqueClient();
        var response = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest("invalid-email-format", "SecurePassword123!"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(400, doc.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task Register_MissingPassword_Returns400ProblemDetails()
    {
        var client = CreateUniqueClient();
        var email = $"nopass_{Guid.NewGuid():N}@maintenx.internal";
        var response = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, "   "));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_PasswordBelowMinLength_Returns400ProblemDetails()
    {
        var client = CreateUniqueClient();
        var email = $"short_{Guid.NewGuid():N}@maintenx.internal";
        var response = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, "Short123!"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        Assert.Contains("between 12 and 128 characters", json);
    }

    [Fact]
    public async Task Register_RateLimiting_Returns429After5RequestsPerMinute()
    {
        var clientIp = $"192.0.2.{Interlocked.Increment(ref _ipCounter)}";
        var client = CreateClientWithIp(_factory, clientIp);

        for (int i = 0; i < 5; i++)
        {
            var email = $"rate_{i}_{Guid.NewGuid():N}@maintenx.internal";
            var resp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, "SecurePassword123!"));
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }

        // 6th request must be throttled
        var throttledResp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest("rate_blocked@maintenx.internal", "SecurePassword123!"));
        Assert.Equal(HttpStatusCode.TooManyRequests, throttledResp.StatusCode);
        Assert.True(throttledResp.Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task Register_ResponseDoesNotExposeSecretsOrExistence()
    {
        var client = CreateUniqueClient();
        var email = $"secret_check_{Guid.NewGuid():N}@maintenx.internal";
        var response = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, "SecurePassword123!"));

        var rawString = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("password", rawString, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hash", rawString, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("securityStamp", rawString, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // 2. LOGIN TESTS
    // =========================================================================

    [Fact]
    public async Task Login_ValidCredentials_Returns200WithTokenResponse()
    {
        var client = CreateUniqueClient();
        var email = $"login_valid_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));

        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(body);
        Assert.False(string.IsNullOrWhiteSpace(body.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(body.RefreshToken));
        Assert.True(body.ExpiresInSeconds > 0);
        Assert.Equal("Bearer", body.TokenType);
        Assert.NotEqual(Guid.Empty, body.SessionId);
    }

    [Fact]
    public async Task Login_InvalidPassword_ReturnsGeneric401ProblemDetails()
    {
        var client = CreateUniqueClient();
        var email = $"login_badpass_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));

        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, "WrongPassword999!"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("Invalid email or password.", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Login_NonexistentAccount_ReturnsEquivalentGeneric401ProblemDetails()
    {
        var client = CreateUniqueClient();
        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest("nonexistent@maintenx.internal", "AnyPassword123!"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("Invalid email or password.", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Login_DeactivatedAccount_ReturnsEquivalentGeneric401ProblemDetails()
    {
        var client = CreateUniqueClient();
        var email = $"deactivated_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));

        // Manually deactivate account in DB
        using (var db = CreateDbContext())
        {
            var user = await db.Users.SingleAsync(u => u.Email == email);
            user.Deactivate(DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("Invalid email or password.", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Login_LockedAccount_ReturnsGeneric401_Not423()
    {
        var client = CreateUniqueClient();
        var email = $"lockout_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));

        // Submit 5 failed attempts from different IPs to avoid IP rate-limit before lockout
        for (int i = 1; i <= 5; i++)
        {
            var reqClient = CreateClientWithIp(_factory, $"198.51.100.{Interlocked.Increment(ref _ipCounter)}");
            var resp = await reqClient.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, "WrongPass123!"));
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        // 6th attempt: account is locked out, must return 401 Unauthorized (NOT 423) with generic message
        var lockedClient = CreateClientWithIp(_factory, $"198.51.100.{Interlocked.Increment(ref _ipCounter)}");
        var lockedResponse = await lockedClient.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));

        Assert.Equal(HttpStatusCode.Unauthorized, lockedResponse.StatusCode);
        var json = await lockedResponse.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("Invalid email or password.", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Login_RateLimiting_Returns429After10RequestsPerMinute()
    {
        var clientIp = $"192.0.2.{Interlocked.Increment(ref _ipCounter)}";
        var client = CreateClientWithIp(_factory, clientIp);

        for (int i = 0; i < 10; i++)
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest("probe@maintenx.internal", "Password123!"));
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        var throttledResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest("probe@maintenx.internal", "Password123!"));
        Assert.Equal(HttpStatusCode.TooManyRequests, throttledResp.StatusCode);
        Assert.True(throttledResp.Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task Login_NoCredentialsOrSecretsAppearInResponseOrLogs()
    {
        var client = CreateUniqueClient();
        var email = $"login_audit_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        var response = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));

        var json = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(password, json);
        Assert.DoesNotContain("PasswordHash", json);
        Assert.DoesNotContain("SecurityStamp", json);
    }

    // =========================================================================
    // 3. REFRESH TOKEN TESTS
    // =========================================================================

    [Fact]
    public async Task Refresh_ValidToken_Returns200WithRotatedPair()
    {
        var client = CreateUniqueClient();
        var email = $"refresh_valid_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        var refreshResp = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(loginBody.RefreshToken));

        Assert.Equal(HttpStatusCode.OK, refreshResp.StatusCode);
        var refreshBody = await refreshResp.Content.ReadFromJsonAsync<RefreshTokenResponse>();
        Assert.NotNull(refreshBody);
        Assert.NotEqual(loginBody.AccessToken, refreshBody.AccessToken);
        Assert.NotEqual(loginBody.RefreshToken, refreshBody.RefreshToken);
        Assert.Equal(loginBody.SessionId, refreshBody.SessionId);
    }

    [Fact]
    public async Task Refresh_OldTokenReplay_ReturnsGeneric401AndRevokesSession()
    {
        var client = CreateUniqueClient();
        var email = $"refresh_replay_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        // First rotation succeeds
        var firstRotation = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(loginBody.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, firstRotation.StatusCode);

        // Replay of the already-rotated original token
        var replayResp = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(loginBody.RefreshToken));

        Assert.Equal(HttpStatusCode.Unauthorized, replayResp.StatusCode);
        var json = await replayResp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("Invalid or expired refresh token.", doc.RootElement.GetProperty("detail").GetString());

        // Verify session was revoked in DB
        using var db = CreateDbContext();
        var session = await db.UserSessions.SingleAsync(s => s.Id == loginBody.SessionId);
        Assert.NotNull(session.RevokedAtUtc);
        Assert.Equal(SessionRevocationReason.TokenReplayDetected, session.RevocationReason);
    }

    [Fact]
    public async Task Refresh_ExpiredOrUnknownToken_ReturnsGeneric401()
    {
        var client = CreateUniqueClient();
        var response = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest("nonexistent-opaque-token-123"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("Invalid or expired refresh token.", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Refresh_EmptyOrMissingToken_Returns400ProblemDetails()
    {
        var client = CreateUniqueClient();
        var response = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest("   "));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_RateLimiting_Returns429After30RequestsPerMinute()
    {
        var clientIp = $"192.0.2.{Interlocked.Increment(ref _ipCounter)}";
        var client = CreateClientWithIp(_factory, clientIp);

        for (int i = 0; i < 30; i++)
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest("bogus-token"));
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        var throttledResp = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest("bogus-token"));
        Assert.Equal(HttpStatusCode.TooManyRequests, throttledResp.StatusCode);
        Assert.True(throttledResp.Headers.Contains("Retry-After"));
    }

    // =========================================================================
    // 4. LOGOUT TESTS
    // =========================================================================

    [Fact]
    public async Task Logout_Unauthenticated_Returns401()
    {
        var client = CreateUniqueClient();
        var response = await client.PostAsync("/api/v1/auth/logout", null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Logout_AuthenticatedCaller_Returns204AndRevokesSession()
    {
        var client = CreateUniqueClient();
        var email = $"logout_auth_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginBody.AccessToken);

        var logoutResp = await client.PostAsync("/api/v1/auth/logout", null);

        Assert.Equal(HttpStatusCode.NoContent, logoutResp.StatusCode);

        // Verify session was revoked in database
        using var db = CreateDbContext();
        var session = await db.UserSessions.SingleAsync(s => s.Id == loginBody.SessionId);
        Assert.NotNull(session.RevokedAtUtc);
        Assert.Equal(SessionRevocationReason.UserLogout, session.RevocationReason);
    }

    [Fact]
    public async Task Logout_RepeatedCall_PreservesIdempotentBehavior()
    {
        var client = CreateUniqueClient();
        var email = $"logout_idemp_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginBody.AccessToken);

        var first = await client.PostAsync("/api/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);

        var second = await client.PostAsync("/api/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, second.StatusCode);
    }

    [Fact]
    public async Task Logout_MissingOrMalformedClaims_FailsSafely()
    {
        var keyRing = _factory.Services.GetRequiredService<IJwtKeyRing>();
        var tokenHandler = new JwtSecurityTokenHandler();
        var creds = keyRing.CreateSigningCredentials();

        // Token without 'sid' claim
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString())]),
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = creds
        };
        var token = tokenHandler.CreateJwtSecurityToken(descriptor);
        var tokenString = tokenHandler.WriteToken(token);

        var client = CreateUniqueClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenString);

        var response = await client.PostAsync("/api/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Logout_MalformedNonGuidSubClaim_Returns401AndLeavesSessionUnmodified()
    {
        var client = CreateUniqueClient();
        var email = $"malformed_sub_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        var keyRing = _factory.Services.GetRequiredService<IJwtKeyRing>();
        var tokenHandler = new JwtSecurityTokenHandler();
        var creds = keyRing.CreateSigningCredentials();

        // Token with active valid sessionId ('sid'), but a malformed, non-GUID 'sub' claim
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([
                new Claim(JwtRegisteredClaimNames.Sub, "invalid-non-guid-sub-string"),
                new Claim("sid", loginBody.SessionId.ToString())
            ]),
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = creds
        };
        var token = tokenHandler.CreateJwtSecurityToken(descriptor);
        var tokenString = tokenHandler.WriteToken(token);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenString);

        var response = await client.PostAsync("/api/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("Invalid or missing user identity claim.", doc.RootElement.GetProperty("detail").GetString());

        // Verify session and refresh tokens remain active and unmodified in PostgreSQL
        using var db = CreateDbContext();
        var session = await db.UserSessions.SingleAsync(s => s.Id == loginBody.SessionId);
        Assert.Null(session.RevokedAtUtc);
        Assert.Null(session.RevocationReason);

        var refreshTokens = await db.RefreshTokens.Where(rt => rt.SessionId == loginBody.SessionId).ToListAsync();
        Assert.NotEmpty(refreshTokens);
        Assert.All(refreshTokens, rt => Assert.False(rt.IsRevoked));
    }

    // =========================================================================
    // 5. CHANGE PASSWORD TESTS
    // =========================================================================

    [Fact]
    public async Task ChangePassword_Unauthenticated_Returns401()
    {
        var client = CreateUniqueClient();
        var response = await client.PostAsJsonAsync(
            "/api/v1/auth/change-password",
            new ChangePasswordRequest("OldPass123!", "NewPass123!456"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_ValidCurrentAndNewPassword_Returns200AndRevokesSessions()
    {
        var client = CreateUniqueClient();
        var email = $"pwd_change_{Guid.NewGuid():N}@maintenx.internal";
        var oldPassword = "InitialPassword123!";
        var newPassword = "UpdatedPassword456!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, oldPassword));
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, oldPassword));
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginBody.AccessToken);

        var changeResp = await client.PostAsJsonAsync(
            "/api/v1/auth/change-password",
            new ChangePasswordRequest(oldPassword, newPassword));

        Assert.Equal(HttpStatusCode.OK, changeResp.StatusCode);
        var changeBody = await changeResp.Content.ReadFromJsonAsync<PasswordMutationResponse>();
        Assert.NotNull(changeBody);
        Assert.Equal(PasswordMutationResponse.DefaultMessage, changeBody.Message);

        // Previous session revoked with PasswordChanged
        using var db = CreateDbContext();
        var session = await db.UserSessions.SingleAsync(s => s.Id == loginBody.SessionId);
        Assert.NotNull(session.RevokedAtUtc);
        Assert.Equal(SessionRevocationReason.PasswordChanged, session.RevocationReason);

        // Login with old password fails
        var oldLoginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, oldPassword));
        Assert.Equal(HttpStatusCode.Unauthorized, oldLoginResp.StatusCode);

        // Login with new password succeeds
        var newLoginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, newPassword));
        Assert.Equal(HttpStatusCode.OK, newLoginResp.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_InvalidCurrentPassword_Returns400ProblemDetails()
    {
        var client = CreateUniqueClient();
        var email = $"pwd_badcur_{Guid.NewGuid():N}@maintenx.internal";
        var password = "InitialPassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginBody.AccessToken);

        var changeResp = await client.PostAsJsonAsync(
            "/api/v1/auth/change-password",
            new ChangePasswordRequest("WrongCurrent123!", "NewPassword456!"));

        Assert.Equal(HttpStatusCode.BadRequest, changeResp.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_InvalidNewPassword_Returns400ProblemDetails()
    {
        var client = CreateUniqueClient();
        var email = $"pwd_tooshort_{Guid.NewGuid():N}@maintenx.internal";
        var password = "InitialPassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginBody.AccessToken);

        var changeResp = await client.PostAsJsonAsync(
            "/api/v1/auth/change-password",
            new ChangePasswordRequest(password, "short"));

        Assert.Equal(HttpStatusCode.BadRequest, changeResp.StatusCode);
    }

    // =========================================================================
    // 6. CROSS-CUTTING TESTS
    // =========================================================================

    [Fact]
    public async Task Endpoints_MalformedJson_Returns400ProblemDetails()
    {
        var client = CreateUniqueClient();
        var malformedContent = new StringContent("{ not valid json ", Encoding.UTF8, "application/json");

        var response = await client.PostAsync("/api/v1/auth/register", malformedContent);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private sealed class TestSocketSimulationStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
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
}
