namespace MaintenX.IntegrationTests;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Common.Modules;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

/// <summary>
/// End-to-end automated testing suite for FEAT-002 (T7).
/// Exercises complete multi-step user authentication lifecycles, session revocation,
/// token replay attack mitigation, lockout recovery, rate limiting, and untrusted proxy isolation
/// against containerized PostgreSQL 16 using WebApplicationFactory.
/// </summary>
public class AuthEndToEndLifecycleTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public AuthEndToEndLifecycleTests()
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
                services.AddSingleton<IModule, TestAuthProbeModule>();
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

    private static int _ipCounter = 1;
    private static string GetNextUniqueIp()
    {
        var id = Interlocked.Increment(ref _ipCounter);
        var b = (id / 250) % 250;
        var c = id % 250 + 1;
        return $"198.51.{b}.{c}";
    }

    private HttpClient CreateUniqueClient()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", GetNextUniqueIp());
        return client;
    }

    private HttpClient CreateClientWithIp(string ipAddress)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ipAddress);
        return client;
    }

    // =========================================================================
    // SCENARIO A: Complete Registration and Authentication Lifecycle
    // =========================================================================

    [Fact]
    public async Task E2E_FullLifecycle_RegisterLoginRefreshProtectedProbeAndLogout_SucceedsEndToEnd()
    {
        var client = CreateUniqueClient();
        var email = $"lifecycle_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        // 1. Register a new user
        var regResp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, regResp.StatusCode);
        var regBody = await regResp.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(regBody);
        Assert.Equal(RegisterResponse.DefaultMessage, regBody.Message);

        // 2. Login with registered credentials
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);
        Assert.False(string.IsNullOrWhiteSpace(loginBody.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(loginBody.RefreshToken));
        Assert.True(loginBody.ExpiresInSeconds > 0);
        Assert.Equal("Bearer", loginBody.TokenType);
        Assert.NotEqual(Guid.Empty, loginBody.SessionId);

        // 3. Call protected endpoint without token -> 401 Unauthorized
        var unauthProbe = await client.GetAsync("/api/v1/test/auth-probe");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthProbe.StatusCode);

        // 4. Call protected endpoint with valid JWT Bearer token -> 200 OK
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginBody.AccessToken);
        var authProbe = await client.GetAsync("/api/v1/test/auth-probe");
        Assert.Equal(HttpStatusCode.OK, authProbe.StatusCode);
        var probeContent = await authProbe.Content.ReadAsStringAsync();
        using var probeDoc = JsonDocument.Parse(probeContent);
        Assert.Equal(loginBody.SessionId.ToString(), probeDoc.RootElement.GetProperty("sid").GetString());

        // 5. Rotate refresh token via JSON body
        client.DefaultRequestHeaders.Authorization = null; // refresh endpoint is anonymous
        var refreshResp = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(loginBody.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, refreshResp.StatusCode);
        var refreshBody = await refreshResp.Content.ReadFromJsonAsync<RefreshTokenResponse>();
        Assert.NotNull(refreshBody);
        Assert.NotEqual(loginBody.AccessToken, refreshBody.AccessToken);
        Assert.NotEqual(loginBody.RefreshToken, refreshBody.RefreshToken);
        Assert.Equal(loginBody.SessionId, refreshBody.SessionId);

        // 6. Verify replacement access token works on protected endpoint
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshBody.AccessToken);
        var probeAfterRefresh = await client.GetAsync("/api/v1/test/auth-probe");
        Assert.Equal(HttpStatusCode.OK, probeAfterRefresh.StatusCode);

        // 7. Logout caller session with active access token
        var logoutResp = await client.PostAsync("/api/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logoutResp.StatusCode);

        // 8. Verify session and refresh tokens are revoked in PostgreSQL
        using var db = CreateDbContext();
        var session = await db.UserSessions.SingleAsync(s => s.Id == loginBody.SessionId);
        Assert.NotNull(session.RevokedAtUtc);
        Assert.Equal(SessionRevocationReason.UserLogout, session.RevocationReason);

        var tokens = await db.RefreshTokens.Where(t => t.SessionId == loginBody.SessionId).ToListAsync();
        Assert.NotEmpty(tokens);
        Assert.All(tokens, t => Assert.True(t.IsRevoked || t.IsRotated));

        // 9. Subsequent refresh attempt with replacement token fails -> 401 Unauthorized
        client.DefaultRequestHeaders.Authorization = null;
        var postLogoutRefresh = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(refreshBody.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, postLogoutRefresh.StatusCode);

        // 10. Attempt to refresh with old rotated token also fails -> 401 Unauthorized
        var oldRefreshAfterLogout = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(loginBody.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, oldRefreshAfterLogout.StatusCode);
    }

    // =========================================================================
    // SCENARIO B: Password Change and Multi-Session Behavior
    // =========================================================================

    [Fact]
    public async Task E2E_PasswordChange_MultiSession_RevokesAllSessionsAndRejectsOldCredentials()
    {
        var clientA = CreateUniqueClient();
        var clientB = CreateUniqueClient();
        var email = $"multisess_{Guid.NewGuid():N}@maintenx.internal";
        var oldPassword = "InitialPassword123!";
        var newPassword = "UpdatedPassword456!";

        // 1. Register user
        await clientA.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, oldPassword));

        // 2. Establish Session 1 on Client A
        var loginRespA = await clientA.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, oldPassword));
        var loginBodyA = await loginRespA.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBodyA);

        // 3. Establish Session 2 on Client B
        var loginRespB = await clientB.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, oldPassword));
        var loginBodyB = await loginRespB.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBodyB);
        Assert.NotEqual(loginBodyA.SessionId, loginBodyB.SessionId);

        // Verify both sessions exist and are active in PostgreSQL
        using (var db = CreateDbContext())
        {
            var userSessions = await db.UserSessions.Where(s => s.Id == loginBodyA.SessionId || s.Id == loginBodyB.SessionId).ToListAsync();
            Assert.Equal(2, userSessions.Count);
            Assert.All(userSessions, s => Assert.Null(s.RevokedAtUtc));
        }

        // 4. Client A changes password through API
        clientA.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginBodyA.AccessToken);
        var changeResp = await clientA.PostAsJsonAsync(
            "/api/v1/auth/change-password",
            new ChangePasswordRequest(oldPassword, newPassword));
        Assert.Equal(HttpStatusCode.OK, changeResp.StatusCode);
        var changeBody = await changeResp.Content.ReadFromJsonAsync<PasswordMutationResponse>();
        Assert.NotNull(changeBody);
        Assert.Equal(PasswordMutationResponse.DefaultMessage, changeBody.Message);

        // 5. Old password cannot authenticate
        var oldLoginResp = await clientA.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, oldPassword));
        Assert.Equal(HttpStatusCode.Unauthorized, oldLoginResp.StatusCode);

        // 6. New password authenticates successfully and returns a new session
        var newLoginResp = await clientA.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, newPassword));
        Assert.Equal(HttpStatusCode.OK, newLoginResp.StatusCode);
        var newLoginBody = await newLoginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(newLoginBody);
        Assert.NotEqual(loginBodyA.SessionId, newLoginBody.SessionId);
        Assert.NotEqual(loginBodyB.SessionId, newLoginBody.SessionId);

        // 7. Refresh tokens from both previous sessions are immediately rejected
        var refreshOldA = await clientA.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(loginBodyA.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, refreshOldA.StatusCode);

        var refreshOldB = await clientB.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(loginBodyB.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, refreshOldB.StatusCode);

        // 8. In PostgreSQL: All previous user sessions are revoked with reason PasswordChanged
        using (var db = CreateDbContext())
        {
            var sessionA = await db.UserSessions.SingleAsync(s => s.Id == loginBodyA.SessionId);
            Assert.NotNull(sessionA.RevokedAtUtc);
            Assert.Equal(SessionRevocationReason.PasswordChanged, sessionA.RevocationReason);

            var sessionB = await db.UserSessions.SingleAsync(s => s.Id == loginBodyB.SessionId);
            Assert.NotNull(sessionB.RevokedAtUtc);
            Assert.Equal(SessionRevocationReason.PasswordChanged, sessionB.RevocationReason);
        }

        // 9. Security stamp validation contract: ISecurityStampValidator reflects rotated stamp
        using (var scope = _factory.Services.CreateScope())
        {
            var stampValidator = scope.ServiceProvider.GetRequiredService<ISecurityStampValidator>();
            using var db = CreateDbContext();
            var user = await db.Users.SingleAsync(u => u.Email == email);

            // Validates that security stamp in DB is updated and validation passes with current stamp
            var isValidCurrent = await stampValidator.ValidateAsync(user.Id, user.SecurityStamp);
            Assert.True(isValidCurrent);

            // An outdated security stamp is rejected
            var isValidStale = await stampValidator.ValidateAsync(user.Id, "stale-security-stamp-pre-mutation");
            Assert.False(isValidStale);
        }
    }

    // =========================================================================
    // SCENARIO C: Refresh-Token Replay and Session-Family Revocation
    // =========================================================================

    [Fact]
    public async Task E2E_RefreshTokenReplay_RevokesSessionFamilyAndLogsAudit_LeavesUnrelatedSessionsIntact()
    {
        var clientUser1 = CreateUniqueClient();
        var clientUser2 = CreateUniqueClient();

        var email1 = $"replay_victim_{Guid.NewGuid():N}@maintenx.internal";
        var email2 = $"unrelated_user_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        // Register and login User 1
        await clientUser1.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email1, password));
        var login1 = await (await clientUser1.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email1, password)))
            .Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(login1);

        // Register and login User 2 (unrelated user)
        await clientUser2.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email2, password));
        var login2 = await (await clientUser2.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email2, password)))
            .Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(login2);

        // User 1 rotates token: R0 -> R1
        var refreshResp1 = await clientUser1.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(login1.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, refreshResp1.StatusCode);
        var refreshBody1 = await refreshResp1.Content.ReadFromJsonAsync<RefreshTokenResponse>();
        Assert.NotNull(refreshBody1);

        // Replay attack: User 1's old token R0 is replayed
        var replayResp = await clientUser1.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(login1.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, replayResp.StatusCode);

        // Verify in PostgreSQL:
        using var db = CreateDbContext();

        // 1. User 1's session family is revoked with TokenReplayDetected
        var session1 = await db.UserSessions.SingleAsync(s => s.Id == login1.SessionId);
        Assert.NotNull(session1.RevokedAtUtc);
        Assert.Equal(SessionRevocationReason.TokenReplayDetected, session1.RevocationReason);

        // 2. Descendant token R1 is revoked (verified in-memory to avoid LINQ-to-SQL translation issues on computed properties)
        var user1Tokens = await db.RefreshTokens
            .Where(t => t.SessionId == login1.SessionId)
            .ToListAsync();
        var activeDescendantTokens = user1Tokens
            .Where(t => !t.IsRevoked && !t.IsRotated)
            .ToList();
        Assert.Empty(activeDescendantTokens);

        // 3. User 2's session is completely unaffected and remains active
        var session2 = await db.UserSessions.SingleAsync(s => s.Id == login2.SessionId);
        Assert.Null(session2.RevokedAtUtc);
        Assert.Null(session2.RevocationReason);

        // 4. SecurityAuditEvent of type TokenReplayDetected is committed for User 1
        var replayAudit = await db.SecurityAuditEvents
            .Where(e => e.EventType == SecurityAuditEventType.TokenReplayDetected && e.SessionId == login1.SessionId)
            .SingleOrDefaultAsync();
        Assert.NotNull(replayAudit);
        Assert.Equal(login1.SessionId, replayAudit.SessionId);

        // 5. Audit metadata contains zero secrets
        var rawAudit = JsonSerializer.Serialize(replayAudit);
        Assert.DoesNotContain(login1.RefreshToken, rawAudit);
        Assert.DoesNotContain(password, rawAudit);

        // 6. Descendant token R1 is now rejected on refresh
        var refreshAfterReplay = await clientUser1.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(refreshBody1.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, refreshAfterReplay.StatusCode);
    }

    [Fact]
    public async Task E2E_ConcurrentRefresh_SingleFlightRotation_AllowsAtMostOneSuccess()
    {
        var client = CreateUniqueClient();
        var email = $"concurrent_refresh_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        var login = await (await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password)))
            .Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(login);

        // Launch two concurrent refresh requests simultaneously with the same token
        var task1 = client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(login.RefreshToken));
        var task2 = client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(login.RefreshToken));

        var responses = await Task.WhenAll(task1, task2);

        var okCount = responses.Count(r => r.StatusCode == HttpStatusCode.OK);
        var unauthCount = responses.Count(r => r.StatusCode == HttpStatusCode.Unauthorized);

        // At most one request can rotate successfully; the other is serialized and detects rotation/replay
        Assert.Equal(1, okCount);
        Assert.Equal(1, unauthCount);
    }

    // =========================================================================
    // SCENARIO D: Login Failure, Lockout, and Recovery
    // =========================================================================

    [Fact]
    public async Task E2E_LoginLockout_FiveFailuresTriggersLockout_ReturnsGeneric401_RecoversAfterWindow()
    {
        var email = $"lockout_e2e_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        var client = CreateUniqueClient();
        await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));

        // Submit 4 consecutive failures from distinct IPs to avoid IP rate limiting
        for (int i = 1; i <= 4; i++)
        {
            var c = CreateClientWithIp(GetNextUniqueIp());
            var resp = await c.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, "WrongPass1!"));
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
            var json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            Assert.Equal("Invalid email or password.", doc.RootElement.GetProperty("detail").GetString());
        }

        // 5th attempt fails and triggers 15-minute lockout
        var fifthClient = CreateClientWithIp(GetNextUniqueIp());
        var fifthResp = await fifthClient.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, "WrongPass1!"));
        Assert.Equal(HttpStatusCode.Unauthorized, fifthResp.StatusCode);

        // Verify in PostgreSQL: User is locked out
        using (var db = CreateDbContext())
        {
            var user = await db.Users.SingleAsync(u => u.Email == email);
            Assert.NotNull(user.LockoutEndUtc);
            Assert.True(user.LockoutEndUtc.Value > DateTime.UtcNow);
        }

        // 6th attempt: Even with VALID credentials, account is locked out and returns generic 401 (never 423)
        var lockedClient = CreateClientWithIp(GetNextUniqueIp());
        var lockedResp = await lockedClient.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.Unauthorized, lockedResp.StatusCode);
        var lockedJson = await lockedResp.Content.ReadAsStringAsync();
        using var lockedDoc = JsonDocument.Parse(lockedJson);
        Assert.Equal("Invalid email or password.", lockedDoc.RootElement.GetProperty("detail").GetString());

        // Deterministic recovery: Simulate that the 15-minute lockout window has elapsed
        using (var db = CreateDbContext())
        {
            await db.Database.ExecuteSqlRawAsync(
                "UPDATE platform.users SET lockout_end_utc = {0} WHERE email = {1}",
                DateTime.UtcNow.AddMinutes(-1),
                email);
        }

        // Subsequent login with valid credentials succeeds without wall-clock sleep
        var recoveredClient = CreateClientWithIp(GetNextUniqueIp());
        var recoveryResp = await recoveredClient.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, recoveryResp.StatusCode);
        var recoveryBody = await recoveryResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(recoveryBody);
        Assert.False(string.IsNullOrWhiteSpace(recoveryBody.AccessToken));

        // In PostgreSQL: Failed login counters and lockout state are cleared
        using (var db = CreateDbContext())
        {
            var user = await db.Users.SingleAsync(u => u.Email == email);
            Assert.Equal(0, user.FailedLoginAttempts);
            Assert.Null(user.LockoutEndUtc);
        }
    }

    // =========================================================================
    // SCENARIO E: Registration and Validation Behavior
    // =========================================================================

    [Fact]
    public async Task E2E_Registration_DuplicateAndCaseInsensitiveEmail_ReturnsUniformGenericResponse()
    {
        var client = CreateUniqueClient();
        var mixedCaseEmail = $"  Alice.SMITH.{Guid.NewGuid():N}@Example.COM  ";
        var normalizedEmail = mixedCaseEmail.Trim().ToLowerInvariant();
        var password = "SecurePassword123!";

        // First registration
        var reg1 = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(mixedCaseEmail, password));
        Assert.Equal(HttpStatusCode.OK, reg1.StatusCode);
        var body1 = await reg1.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(body1);
        Assert.Equal(RegisterResponse.DefaultMessage, body1.Message);

        // Duplicate registration with clean lowercase
        var reg2 = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(normalizedEmail, password));
        Assert.Equal(HttpStatusCode.OK, reg2.StatusCode);
        var body2 = await reg2.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(body2);
        Assert.Equal(RegisterResponse.DefaultMessage, body2.Message);

        // Exactly one user persisted
        using var db = CreateDbContext();
        var count = await db.Users.CountAsync(u => u.Email == normalizedEmail);
        Assert.Equal(1, count);

        // Login with lowercase email succeeds
        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(normalizedEmail, password));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task E2E_Registration_InputValidation_RejectsInvalidPayloadsSafely()
    {
        var client = CreateUniqueClient();

        // 1. Password below minimum length (< 12)
        var shortPassResp = await client.PostAsJsonAsync(
            "/api/v1/auth/register",
            new RegisterRequest("valid@example.com", "Short1!"));
        Assert.Equal(HttpStatusCode.BadRequest, shortPassResp.StatusCode);

        // 2. Password above maximum length (> 128)
        var longPass = new string('A', 129);
        var longPassResp = await client.PostAsJsonAsync(
            "/api/v1/auth/register",
            new RegisterRequest("valid@example.com", longPass));
        Assert.Equal(HttpStatusCode.BadRequest, longPassResp.StatusCode);

        // 3. Empty password
        var emptyPassResp = await client.PostAsJsonAsync(
            "/api/v1/auth/register",
            new RegisterRequest("valid@example.com", ""));
        Assert.Equal(HttpStatusCode.BadRequest, emptyPassResp.StatusCode);

        // 4. Malformed JSON
        var malformedContent = new StringContent("{ \"email\": \"incomplete json ", Encoding.UTF8, "application/json");
        var malformedResp = await client.PostAsync("/api/v1/auth/register", malformedContent);
        Assert.Equal(HttpStatusCode.BadRequest, malformedResp.StatusCode);

        // 5. Oversized payload (100 KB payload)
        var largePadding = new string('x', 100 * 1024);
        var largeContent = new StringContent(
            JsonSerializer.Serialize(new { email = "large@example.com", password = "SecurePassword123!", padding = largePadding }),
            Encoding.UTF8,
            "application/json");
        var largeResp = await client.PostAsync("/api/v1/auth/register", largeContent);
        // Validates that request is either rejected or successfully bounded without crashing the pipeline
        Assert.True(largeResp.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.OK);

        // 6. Zero secret leakage across error payloads
        var shortPassBody = await shortPassResp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Short1!", shortPassBody);
        Assert.DoesNotContain("PasswordHash", shortPassBody);
        Assert.DoesNotContain("SecurityStamp", shortPassBody);
    }

    // =========================================================================
    // SCENARIO F: Rate Limiting and Forwarded Headers
    // =========================================================================

    [Fact]
    public async Task E2E_RateLimiting_EnforcesPermitLimitsAcrossEndpoints_AndReturnsRetryAfter()
    {
        // 1. Registration endpoint: 5 req/min
        var regIp = GetNextUniqueIp();
        var regClient = CreateClientWithIp(regIp);

        for (int i = 0; i < 5; i++)
        {
            var r = await regClient.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest($"reg_rl_{i}_{Guid.NewGuid():N}@example.com", "SecurePassword123!"));
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        }
        var regThrottled = await regClient.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest("reg_rl_over@example.com", "SecurePassword123!"));
        Assert.Equal(HttpStatusCode.TooManyRequests, regThrottled.StatusCode);
        Assert.True(regThrottled.Headers.Contains("Retry-After"));

        // 2. Login endpoint: 10 req/min
        var loginIp = GetNextUniqueIp();
        var loginClient = CreateClientWithIp(loginIp);

        for (int i = 0; i < 10; i++)
        {
            var r = await loginClient.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest("probe@example.com", "WrongPass123!"));
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        }
        var loginThrottled = await loginClient.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest("probe@example.com", "WrongPass123!"));
        Assert.Equal(HttpStatusCode.TooManyRequests, loginThrottled.StatusCode);
        Assert.True(loginThrottled.Headers.Contains("Retry-After"));

        // 3. Refresh endpoint: 30 req/min
        var refreshIp = GetNextUniqueIp();
        var refreshClient = CreateClientWithIp(refreshIp);

        for (int i = 0; i < 30; i++)
        {
            var r = await refreshClient.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(""));
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        }
        var refreshThrottled = await refreshClient.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(""));
        Assert.Equal(HttpStatusCode.TooManyRequests, refreshThrottled.StatusCode);
        Assert.True(refreshThrottled.Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task E2E_RateLimiting_UntrustedForwardedHeaders_CannotEvadeRateLimiter()
    {
        // Untrusted socket IP (not in KnownProxies)
        var untrustedSocketIp = GetNextUniqueIp();
        var client = CreateClientWithIp(untrustedSocketIp);

        // Attacker attempts to spoof X-Forwarded-For with varying IPs on each request
        for (int i = 1; i <= 10; i++)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login")
            {
                Content = JsonContent.Create(new LoginRequest("attacker@example.com", "Password123!"))
            };
            request.Headers.Add("X-Forwarded-For", $"10.0.0.{i}");

            var resp = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        // 11th request: Spoofed header should NOT evade the rate limiter because socket IP is untrusted
        var evadedRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login")
        {
            Content = JsonContent.Create(new LoginRequest("attacker@example.com", "Password123!"))
        };
        evadedRequest.Headers.Add("X-Forwarded-For", "10.0.0.99");

        var throttledResp = await client.SendAsync(evadedRequest);
        Assert.Equal(HttpStatusCode.TooManyRequests, throttledResp.StatusCode);
        Assert.True(throttledResp.Headers.Contains("Retry-After"));
    }

    // =========================================================================
    // Test Infrastructure Helpers
    // =========================================================================

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

    private sealed class TestAuthProbeModule : IModule
    {
        public IServiceCollection RegisterModule(IServiceCollection services, IConfiguration configuration) => services;

        public IEndpointRouteBuilder MapEndpoints(IEndpointRouteBuilder endpoints)
        {
            endpoints.MapGet("/api/v1/test/auth-probe", (ClaimsPrincipal user) =>
            {
                var sub = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.FindFirstValue("sub");
                var sid = user.FindFirstValue("sid");
                return Results.Ok(new { sub, sid });
            })
            .RequireAuthorization();

            return endpoints;
        }
    }
}
