namespace MaintenX.IntegrationTests;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

/// <summary>
/// Regression tests for FEAT-003-SEC-001 (TD-09, TD-10, TD-11):
/// - TD-09: Uniform 404 anti-enumeration across unknown, non-member, inactive, and revoked-member tenants (UUID & slug).
/// - TD-10: 30-day absolute session lifetime enforcement across refresh-token rotation and boundary transitions.
/// - TD-11: Tenancy.Standard (30 req/min/user) shared quota, 31st-request 429 + Retry-After, and user isolation.
/// </summary>
public class TenantSecurityRemediationHttpIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private readonly MutableTimeProvider _timeProvider = new(DateTimeOffset.UtcNow);
    private WebApplicationFactory<Program> _factory = null!;

    public TenantSecurityRemediationHttpIntegrationTests()
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
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(_timeProvider);
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

    private static int _ipCounter = 1400;
    private HttpClient CreateClientForIp(string? explicitIp = null)
    {
        var ip = !string.IsNullOrWhiteSpace(explicitIp)
            ? explicitIp
            : $"198.51.{(Interlocked.Increment(ref _ipCounter) / 250) % 250}.{_ipCounter % 250 + 1}";

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ip);
        return client;
    }

    private async Task<(HttpClient Client, User User, LoginResponse Login, Guid SessionId)> CreateAuthenticatedUserAsync(
        string prefix = "rem_user",
        string? explicitIp = null)
    {
        var client = CreateClientForIp(explicitIp);
        var email = $"{prefix}_{Guid.NewGuid():N}@maintenx.dev";
        var password = "SecurePassword123!";

        var regResp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, regResp.StatusCode);

        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);

        var body = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(body);

        using var db = CreateDbContext();
        var user = await db.Users.FirstAsync(u => u.Email == email);
        var session = await db.UserSessions.FirstAsync(s => s.UserId == user.Id && s.RevokedAtUtc == null);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.AccessToken);
        return (client, user, body, session.Id);
    }

    private sealed class MutableTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow;

        public MutableTimeProvider(DateTimeOffset initialUtcNow) => _utcNow = initialUtcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);
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

    // =========================================================================
    // 1. TD-09 — TENANT ANTI-ENUMERATION (UUID & SLUG)
    // =========================================================================

    [Fact]
    public async Task TD09_UnknownAndUnauthorizedTenantsByUuidAndSlug_ReturnIdenticalGeneric404()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("td09_owner");
        var (probeClient, probeUser, _, _) = await CreateAuthenticatedUserAsync("td09_probe");

        // Seed Active, PendingOnboarding, Suspended, Deactivated, and Revoked-membership tenants
        var activeSlug = $"act-{Guid.NewGuid():N}"[..20];
        var pendingSlug = $"pnd-{Guid.NewGuid():N}"[..20];
        var suspendedSlug = $"sus-{Guid.NewGuid():N}"[..20];
        var deactivatedSlug = $"dea-{Guid.NewGuid():N}"[..20];
        var revokedSlug = $"rev-{Guid.NewGuid():N}"[..20];

        Guid activeId, pendingId, suspendedId, deactivatedId, revokedId;

        using (var db = CreateDbContext())
        {
            var tActive = Tenant.Create(activeSlug, "Active Secret", TenantStatus.Active);
            var tPending = Tenant.Create(pendingSlug, "Pending Secret", TenantStatus.PendingOnboarding);
            var tSuspended = Tenant.Create(suspendedSlug, "Suspended Secret", TenantStatus.Suspended);
            var tDeactivated = Tenant.Create(deactivatedSlug, "Deactivated Secret", TenantStatus.Deactivated);
            var tRevoked = Tenant.Create(revokedSlug, "Revoked Secret", TenantStatus.Active);

            db.Tenants.AddRange(tActive, tPending, tSuspended, tDeactivated, tRevoked);

            using (db.CreatePrivilegedTenantBypassScope("td09-seed"))
            {
                var revokedMem = TenantMembership.Create(tRevoked.Id, probeUser.Id, TenantMembershipRole.Member);
                revokedMem.Revoke(DateTime.UtcNow);
                db.TenantMemberships.Add(revokedMem);
                await db.SaveChangesAsync();
            }

            activeId = tActive.Id;
            pendingId = tPending.Id;
            suspendedId = tSuspended.Id;
            deactivatedId = tDeactivated.Id;
            revokedId = tRevoked.Id;
        }

        var probeIdentifiers = new[]
        {
            Guid.NewGuid().ToString(),       // Unknown UUID
            activeId.ToString(),             // Existing Active UUID (no membership)
            $"unknown-{Guid.NewGuid():N}"[..20], // Unknown slug
            activeSlug,                      // Existing Active slug (no membership)
            pendingId.ToString(),            // Existing PendingOnboarding (no membership)
            suspendedId.ToString(),          // Existing Suspended (no membership)
            deactivatedId.ToString(),        // Existing Deactivated (no membership)
            revokedId.ToString()             // Existing Active with historical Revoked membership
        };

        ProblemDetails? baseline = null;

        foreach (var identifier in probeIdentifiers)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenancy/current");
            req.Headers.Add("X-Tenant-ID", identifier);
            var resp = await probeClient.SendAsync(req);

            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
            Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);

            var problem = await resp.Content.ReadFromJsonAsync<ProblemDetails>();
            Assert.NotNull(problem);
            Assert.Equal(404, problem.Status);
            Assert.Equal("Not Found", problem.Title);
            Assert.Equal("The requested tenant organization was not found.", problem.Detail);

            if (baseline is null)
            {
                baseline = problem;
            }
            else
            {
                Assert.Equal(baseline.Title, problem.Title);
                Assert.Equal(baseline.Detail, problem.Detail);
                Assert.Equal(baseline.Status, problem.Status);
            }
        }
    }

    // =========================================================================
    // 2. TD-10 — ABSOLUTE SESSION LIFETIME (30 DAYS)
    // =========================================================================

    [Fact]
    public async Task TD10_RefreshChainAndAbsoluteSessionBoundary_EnforcedAcrossTimeProgression()
    {
        var t0 = _timeProvider.GetUtcNow();
        var (client, user, login, sessionId) = await CreateAuthenticatedUserAsync("td10_abs");

        // 1. Verify initial 30-day absolute session expiry and 7-day refresh token expiry
        using (var db = CreateDbContext())
        {
            var session = await db.UserSessions.AsNoTracking().SingleAsync(s => s.Id == sessionId);
            Assert.Equal(t0.UtcDateTime.AddDays(30), session.ExpiresAtUtc, TimeSpan.FromSeconds(2));

            var rt = await db.RefreshTokens.AsNoTracking().SingleAsync(r => r.SessionId == sessionId);
            Assert.Equal(t0.UtcDateTime.AddDays(7), rt.ExpiresAtUtc, TimeSpan.FromSeconds(2));

            // RecordActivity must NOT extend ExpiresAtUtc
            var domainSession = UserSession.Create(session.UserId, t0.UtcDateTime, TimeSpan.FromDays(30));
            domainSession.RecordActivity(t0.UtcDateTime.AddDays(10));
            Assert.Equal(t0.UtcDateTime.AddDays(30), domainSession.ExpiresAtUtc);
        }

        // 2. Walk refresh chain every 6 days (within 7-day refresh token lifetime): Day 6 -> Day 12 -> Day 18 -> Day 24
        var currentRefreshToken = login.RefreshToken;
        for (var step = 1; step <= 4; step++)
        {
            _timeProvider.Advance(TimeSpan.FromDays(6));
            var stepResp = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(currentRefreshToken));
            Assert.Equal(HttpStatusCode.OK, stepResp.StatusCode);
            var stepBody = await stepResp.Content.ReadFromJsonAsync<RefreshTokenResponse>();
            Assert.NotNull(stepBody);
            currentRefreshToken = stepBody.RefreshToken;

            using var db = CreateDbContext();
            var session = await db.UserSessions.AsNoTracking().SingleAsync(s => s.Id == sessionId);
            Assert.Equal(t0.UtcDateTime.AddDays(30), session.ExpiresAtUtc, TimeSpan.FromSeconds(2));
        }

        // At Day 24, the newly issued refresh token MUST be capped at t0 + 30 days (not t0 + 31 days)
        using (var db = CreateDbContext())
        {
            var latestRt = await db.RefreshTokens
                .AsNoTracking()
                .Where(r => r.SessionId == sessionId && r.RevokedAtUtc == null)
                .SingleAsync();
            Assert.True(latestRt.ExpiresAtUtc <= t0.UtcDateTime.AddDays(30).AddSeconds(2));
        }

        // 3. Advance to Day 29 23:59 (1 minute before absolute boundary) -> refresh succeeds, issues fresh JWT
        _timeProvider.Advance(TimeSpan.FromDays(5) + TimeSpan.FromHours(23) + TimeSpan.FromMinutes(59));
        var refreshBeforeBoundaryResp = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(currentRefreshToken));
        Assert.Equal(HttpStatusCode.OK, refreshBeforeBoundaryResp.StatusCode);
        var refreshBeforeBoundary = await refreshBeforeBoundaryResp.Content.ReadFromJsonAsync<RefreshTokenResponse>();
        Assert.NotNull(refreshBeforeBoundary);

        // 4. Advance 1 minute to exact 30-day absolute boundary
        _timeProvider.Advance(TimeSpan.FromMinutes(1));

        // Non-expired JWT minted 1 minute ago must be REJECTED (401) because session reached absolute expiry
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshBeforeBoundary.AccessToken);
        var meAtBoundary = await client.GetAsync("/api/v1/tenants/me");
        Assert.Equal(HttpStatusCode.Unauthorized, meAtBoundary.StatusCode);

        // Refresh at exact absolute boundary must be REJECTED (401) and create NO new session
        var refreshAtBoundary = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(refreshBeforeBoundary.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, refreshAtBoundary.StatusCode);

        // 5. Advance past 30-day boundary -> refresh still REJECTED (401)
        _timeProvider.Advance(TimeSpan.FromHours(1));
        var refreshPastBoundary = await client.PostAsJsonAsync("/api/v1/auth/refresh", new RefreshTokenRequest(refreshBeforeBoundary.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, refreshPastBoundary.StatusCode);

        using (var db = CreateDbContext())
        {
            var sessionCount = await db.UserSessions.CountAsync(s => s.UserId == user.Id);
            Assert.Equal(1, sessionCount);
        }
    }

    // =========================================================================
    // 3. TD-11 — STANDARD TENANCY RATE LIMIT (30 REQ/MIN/USER)
    // =========================================================================

    [Fact]
    public async Task TD11_StandardRateLimit_Allows30SharedRequests_Rejects31stWith429AndRetryAfter_AndIsolatesUsers()
    {
        const string sharedIp = "198.51.100.123";
        var (userAClient, _, _, _) = await CreateAuthenticatedUserAsync("td11_user_a", sharedIp);
        var (userBClient, _, _, _) = await CreateAuthenticatedUserAsync("td11_user_b", sharedIp);

        // Create an Active tenant for User A (uses Tenancy.Onboarding, NOT Tenancy.Standard)
        var slug = $"td11-{Guid.NewGuid():N}"[..20];
        var createResp = await userAClient.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, "TD11 Org"));
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);
        var created = await createResp.Content.ReadFromJsonAsync<CreateTenantResponse>();
        Assert.NotNull(created);

        long currentVersion;
        using (var db = CreateDbContext())
        {
            var tenant = await db.Tenants.SingleAsync(t => t.Id == created.TenantId);
            tenant.Activate(DateTime.UtcNow);
            await db.SaveChangesAsync();
            currentVersion = tenant.Version;
        }

        userAClient.DefaultRequestHeaders.Add("X-Tenant-ID", created.TenantId.ToString());

        // 1. Send 30 valid requests across GET /me (10), GET /{id} (10), and PATCH /{id} (10)
        for (var i = 0; i < 10; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await userAClient.GetAsync("/api/v1/tenants/me")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await userAClient.GetAsync($"/api/v1/tenants/{created.TenantId}")).StatusCode);

            var patchResp = await userAClient.PatchAsJsonAsync(
                $"/api/v1/tenants/{created.TenantId}",
                new UpdateTenantRequest($"TD11 Org v{i + 1}", currentVersion));
            Assert.Equal(HttpStatusCode.OK, patchResp.StatusCode);
            var updated = await patchResp.Content.ReadFromJsonAsync<TenantResponse>();
            currentVersion = updated!.Version;
        }

        // 2. 31st request (PATCH) returns 429 Too Many Requests with Retry-After and ProblemDetails, and does NOT mutate DB
        var thirtyFirstResp = await userAClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{created.TenantId}",
            new UpdateTenantRequest("Should Not Persist", currentVersion));

        Assert.Equal(HttpStatusCode.TooManyRequests, thirtyFirstResp.StatusCode);
        Assert.True(thirtyFirstResp.Headers.TryGetValues("Retry-After", out var retryValues));
        Assert.True(int.TryParse(retryValues.First(), out var retrySeconds) && retrySeconds > 0);
        Assert.Equal("application/problem+json", thirtyFirstResp.Content.Headers.ContentType?.MediaType);

        var problem = await thirtyFirstResp.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal(429, problem.Status);

        using (var db = CreateDbContext())
        {
            var tenant = await db.Tenants.AsNoTracking().SingleAsync(t => t.Id == created.TenantId);
            Assert.Equal("TD11 Org v10", tenant.DisplayName);
            Assert.Equal(currentVersion, tenant.Version);

            var auditCount = await db.TenantAuditEvents
                .CountAsync(e => e.TenantId == created.TenantId && e.Action == "TenantSettingsUpdated");
            Assert.Equal(10, auditCount);
        }

        // 3. Changing X-Tenant-ID or adding forged userId query param does NOT bypass User A's quota
        userAClient.DefaultRequestHeaders.Remove("X-Tenant-ID");
        userAClient.DefaultRequestHeaders.Add("X-Tenant-ID", Guid.NewGuid().ToString());
        var bypassAttempt = await userAClient.GetAsync($"/api/v1/tenants/me?userId={Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.TooManyRequests, bypassAttempt.StatusCode);

        // 4. Tenancy.Onboarding retains its separate 5-request quota for User A
        var onboardResp = await userAClient.PostAsJsonAsync(
            "/api/v1/tenants",
            new CreateTenantRequest($"td11-onb-{Guid.NewGuid():N}"[..20], "Separate Onboarding Quota"));
        Assert.Equal(HttpStatusCode.Created, onboardResp.StatusCode);

        // 5. User B on the exact same IP has an independent Tenancy.Standard quota
        var userBResp = await userBClient.GetAsync("/api/v1/tenants/me");
        Assert.Equal(HttpStatusCode.OK, userBResp.StatusCode);
    }
}
