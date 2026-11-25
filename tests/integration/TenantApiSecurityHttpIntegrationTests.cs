namespace MaintenX.IntegrationTests;

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Auth.Services;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Configuration;
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
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

/// <summary>
/// Comprehensive HTTP Security & Final Integration Verification tests for FEAT-003 Task 3.6.5.
/// Verifies middleware ordering (Authentication -> RateLimiter -> Authorization -> TenantResolution),
/// verified-user rate-limit partitioning, Retry-After and ProblemDetails contracts,
/// JWT/session/security-stamp/absolute-lifetime enforcement, end-to-end onboarding rollback,
/// multi-workspace switching & parallel isolation, post-discovery status changes, and OpenAPI schema.
/// </summary>
public class TenantApiSecurityHttpIntegrationTests : IAsyncLifetime
{
    private const string TestJwtSecret = "ZGV2LWtleS0yMDI2LXYxLWZlYXQtMDAyLWF1dGgtc2VjdXJpdHktY29uZmlndXJhdGlvbg==";
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public TenantApiSecurityHttpIntegrationTests()
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

    private static int _ipCounter = 1100;
    private HttpClient CreateClientForIp(string? explicitIp = null)
    {
        string ip;
        if (!string.IsNullOrWhiteSpace(explicitIp))
        {
            ip = explicitIp;
        }
        else
        {
            var id = Interlocked.Increment(ref _ipCounter);
            ip = $"198.51.{(id / 250) % 250}.{id % 250 + 1}";
        }

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ip);
        return client;
    }

    private async Task<(HttpClient Client, User User, string Token, Guid SessionId)> CreateAuthenticatedUserAsync(
        string prefix = "sec_user",
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
        return (client, user, body.AccessToken, session.Id);
    }

    private async Task<TenantResponse> CreateActiveTenantWithOwnerAsync(HttpClient ownerClient, string displayName)
    {
        var slug = $"sec-{Guid.NewGuid():N}"[..24];
        var createResp = await ownerClient.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, displayName));
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);
        var created = await createResp.Content.ReadFromJsonAsync<CreateTenantResponse>();
        Assert.NotNull(created);

        using var db = CreateDbContext();
        var tenant = await db.Tenants.SingleAsync(t => t.Id == created.TenantId);
        tenant.Activate(DateTime.UtcNow);
        await db.SaveChangesAsync();

        return new TenantResponse(
            tenant.Id,
            tenant.Slug,
            tenant.DisplayName,
            tenant.Status.ToString(),
            tenant.CreatedAtUtc,
            tenant.UpdatedAtUtc,
            tenant.Version);
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
    // 1. RATE-LIMITING MIDDLEWARE ORDER & PARTITIONING
    // =========================================================================

    [Fact]
    public async Task RateLimiting_Onboarding_SixthRequestReturns429WithRetryAfterProblemDetailsAndNoDbRecord()
    {
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("rl_sixth");

        // First 5 requests succeed (201 Created)
        for (var i = 1; i <= 5; i++)
        {
            var slug = $"rl-{i}-{Guid.NewGuid():N}"[..24];
            var resp = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, $"RL Org {i}"));
            Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        }

        // 6th request is rejected with 429 Too Many Requests
        var rejectedSlug = $"rl-6-{Guid.NewGuid():N}"[..24];
        var sixthResp = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(rejectedSlug, "RL Org 6"));

        Assert.Equal(HttpStatusCode.TooManyRequests, sixthResp.StatusCode);
        Assert.True(sixthResp.Headers.TryGetValues("Retry-After", out var retryValues));
        Assert.True(int.TryParse(retryValues.First(), out var retrySeconds) && retrySeconds > 0);
        Assert.Equal("application/problem+json", sixthResp.Content.Headers.ContentType?.MediaType);

        var problem = await sixthResp.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal(429, problem.Status);

        // Verify rejected slug did not create a DB record
        using var db = CreateDbContext();
        Assert.False(await db.Tenants.AnyAsync(t => t.Slug == rejectedSlug));
    }

    [Fact]
    public async Task RateLimiting_TwoAuthenticatedUsersOnSameIp_HaveIndependentPartitions()
    {
        const string sharedIp = "198.51.100.77";
        var (userAClient, _, _, _) = await CreateAuthenticatedUserAsync("rl_sameip_a", sharedIp);
        var (userBClient, _, _, _) = await CreateAuthenticatedUserAsync("rl_sameip_b", sharedIp);

        // User A exhausts all 5 onboarding permits on sharedIp
        for (var i = 1; i <= 5; i++)
        {
            var slug = $"ipa-{i}-{Guid.NewGuid():N}"[..24];
            var resp = await userAClient.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, $"IP A {i}"));
            Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        }

        var userASixth = await userAClient.PostAsJsonAsync(
            "/api/v1/tenants",
            new CreateTenantRequest($"ipa-6-{Guid.NewGuid():N}"[..24], "IP A 6"));
        Assert.Equal(HttpStatusCode.TooManyRequests, userASixth.StatusCode);

        // User B on the EXACT SAME IP still has full independent user-partition quota
        var userBFirst = await userBClient.PostAsJsonAsync(
            "/api/v1/tenants",
            new CreateTenantRequest($"ipb-1-{Guid.NewGuid():N}"[..24], "IP B 1"));
        Assert.Equal(HttpStatusCode.Created, userBFirst.StatusCode);
    }

    [Fact]
    public async Task RateLimiting_TamperedHeadersAndPayloads_CannotBypassUserPartition()
    {
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("rl_bypass");

        for (var i = 1; i <= 5; i++)
        {
            var resp = await client.PostAsJsonAsync(
                "/api/v1/tenants",
                new CreateTenantRequest($"byp-{i}-{Guid.NewGuid():N}"[..24], $"Bypass {i}"));
            Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        }

        // Attempt bypass using different X-Tenant-ID, untrusted X-Forwarded-For, and forged creatorUserId
        client.DefaultRequestHeaders.Add("X-Tenant-ID", Guid.NewGuid().ToString());
        client.DefaultRequestHeaders.Add("X-Forwarded-For", "203.0.113.250");
        var bypassResp = await client.PostAsJsonAsync("/api/v1/tenants", new
        {
            slug = $"byp-6-{Guid.NewGuid():N}"[..24],
            displayName = "Bypass Attempt",
            creatorUserId = Guid.NewGuid()
        });

        Assert.Equal(HttpStatusCode.TooManyRequests, bypassResp.StatusCode);
    }

    [Fact]
    public async Task RateLimiting_AnonymousLoginEndpoint_RemainsProtectedAfterMiddlewareReorder()
    {
        var client = CreateClientForIp("198.51.100.88");

        // Auth.Login defaults to 10 req/min/IP
        for (var i = 0; i < 10; i++)
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest("nonexistent@maintenx.dev", "WrongPass123!"));
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        var eleventh = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest("nonexistent@maintenx.dev", "WrongPass123!"));
        Assert.Equal(HttpStatusCode.TooManyRequests, eleventh.StatusCode);
    }

    // =========================================================================
    // 2. AUTHENTICATION & TRUSTED ACTOR SECURITY
    // =========================================================================

    [Fact]
    public async Task Auth_InvalidExpiredMissingClaimsAndTamperedTokens_RejectedWith401()
    {
        var (_, userA, tokenA, sessionAId) = await CreateAuthenticatedUserAsync("jwt_a");
        var (_, userB, _, _) = await CreateAuthenticatedUserAsync("jwt_b");

        using var scope = _factory.Services.CreateScope();
        var jwtOptions = scope.ServiceProvider.GetRequiredService<IOptions<JwtOptions>>().Value;
        var keyBytes = Encoding.UTF8.GetBytes(TestJwtSecret);
        var creds = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);

        string MintCustomToken(IEnumerable<Claim> claims, DateTime expiresUtc, string kid)
        {
            var token = new JwtSecurityToken(
                issuer: jwtOptions.Issuer,
                audience: jwtOptions.Audience,
                claims: claims,
                notBefore: expiresUtc.AddMinutes(-15),
                expires: expiresUtc,
                signingCredentials: creds);
            token.Header["kid"] = kid;
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        var client = CreateClientForIp();
        var activeKid = new JwtSecurityTokenHandler().ReadJwtToken(tokenA).Header.Kid;

        // 1. Missing JWT -> 401
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/tenants/me")).StatusCode);

        // 2. Invalid JWT -> 401
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "not.a.valid.jwt");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/tenants/me")).StatusCode);

        // 3. Expired JWT -> 401
        var expiredJwt = MintCustomToken(
            new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userA.Id.ToString()),
                new Claim("sid", sessionAId.ToString()),
                new Claim("sst", userA.SecurityStamp)
            },
            DateTime.UtcNow.AddMinutes(-5),
            activeKid);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", expiredJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/tenants/me")).StatusCode);

        // 4. Missing sid claim -> 401
        var missingSidJwt = MintCustomToken(
            new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userA.Id.ToString()),
                new Claim("sst", userA.SecurityStamp)
            },
            DateTime.UtcNow.AddMinutes(5),
            activeKid);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", missingSidJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/tenants/me")).StatusCode);

        // 5. Session belonging to User A paired with User B's sub -> 401
        var mismatchedSessionJwt = MintCustomToken(
            new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userB.Id.ToString()),
                new Claim("sid", sessionAId.ToString()),
                new Claim("sst", userB.SecurityStamp)
            },
            DateTime.UtcNow.AddMinutes(5),
            activeKid);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", mismatchedSessionJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/tenants/me")).StatusCode);

        // 6. Tampered security stamp -> 401
        var tamperedStampJwt = MintCustomToken(
            new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userA.Id.ToString()),
                new Claim("sid", sessionAId.ToString()),
                new Claim("sst", "tampered-stamp")
            },
            DateTime.UtcNow.AddMinutes(5),
            activeKid);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tamperedStampJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/tenants/me")).StatusCode);

        // 7. Expired UserSession (absolute lifetime boundary in DB) -> 401
        using (var db = CreateDbContext())
        {
            await db.Database.ExecuteSqlRawAsync(
                "UPDATE platform.user_sessions SET expires_at_utc = {0} WHERE id = {1}",
                DateTime.UtcNow.AddMinutes(-1),
                sessionAId);
        }

        var validJwtForExpiredSession = MintCustomToken(
            new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userA.Id.ToString()),
                new Claim("sid", sessionAId.ToString()),
                new Claim("sst", userA.SecurityStamp)
            },
            DateTime.UtcNow.AddMinutes(5),
            activeKid);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", validJwtForExpiredSession);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/tenants/me")).StatusCode);
    }

    // =========================================================================
    // 3. END-TO-END WORKFLOWS (ONBOARDING ROLLBACK, WORKSPACES, STATUS CHANGES)
    // =========================================================================

    [Fact]
    public async Task Workflow1_HttpOnboarding_MembershipFailureRollsBackTenantAtomically()
    {
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("onb_rollback");
        var slug = $"rb-org-{Guid.NewGuid():N}"[..24];

        using (var db = CreateDbContext())
        {
            await db.Database.ExecuteSqlRawAsync(@"
                CREATE OR REPLACE FUNCTION platform.fail_membership_insert()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'Simulated membership persistence failure';
                END;
                $$ LANGUAGE plpgsql;

                CREATE TRIGGER trg_fail_membership_insert
                BEFORE INSERT ON platform.tenant_memberships
                FOR EACH ROW EXECUTE FUNCTION platform.fail_membership_insert();");
        }

        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, "Rollback Org"));
            Assert.Equal(HttpStatusCode.InternalServerError, resp.StatusCode);

            using var verifyDb = CreateDbContext();
            Assert.False(await verifyDb.Tenants.AnyAsync(t => t.Slug == slug));
        }
        finally
        {
            using var cleanupDb = CreateDbContext();
            await cleanupDb.Database.ExecuteSqlRawAsync(@"
                DROP TRIGGER IF EXISTS trg_fail_membership_insert ON platform.tenant_memberships;
                DROP FUNCTION IF EXISTS platform.fail_membership_insert();");
        }
    }

    [Fact]
    public async Task Workflow2_MultipleWorkspaces_SwitchingAndParallelIsolation()
    {
        var (client1, _, _, _) = await CreateAuthenticatedUserAsync("ws_user1");
        var (client2, _, _, _) = await CreateAuthenticatedUserAsync("ws_user2");

        var tenantA = await CreateActiveTenantWithOwnerAsync(client1, "Alpha Workspace");
        var tenantB = await CreateActiveTenantWithOwnerAsync(client1, "Beta Workspace");

        var pendingSlug = $"pend-{Guid.NewGuid():N}"[..24];
        var pendingResp = await client1.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(pendingSlug, "Gamma Pending"));
        Assert.Equal(HttpStatusCode.Created, pendingResp.StatusCode);

        var tenantC = await CreateActiveTenantWithOwnerAsync(client2, "User2 Workspace");

        // 1. Discovery returns deterministic order and accurate IsSelectable
        var discResp = await client1.GetAsync("/api/v1/tenants/me");
        Assert.Equal(HttpStatusCode.OK, discResp.StatusCode);
        var memberships = await discResp.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(memberships);
        Assert.Equal(3, memberships.Count);
        Assert.Equal("Alpha Workspace", memberships[0].TenantDisplayName);
        Assert.True(memberships[0].IsSelectable);
        Assert.Equal("Beta Workspace", memberships[1].TenantDisplayName);
        Assert.True(memberships[1].IsSelectable);
        Assert.Equal("Gamma Pending", memberships[2].TenantDisplayName);
        Assert.False(memberships[2].IsSelectable);

        // 2. Switch to Tenant A, then Tenant B, then verify no leakage without header
        using var reqA = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenancy/current");
        reqA.Headers.Add("X-Tenant-ID", tenantA.Id.ToString());
        var resA = await client1.SendAsync(reqA);
        Assert.Equal(HttpStatusCode.OK, resA.StatusCode);
        Assert.Equal(tenantA.Id, (await resA.Content.ReadFromJsonAsync<CurrentTenantContextResponse>())!.TenantId);

        using var reqB = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenancy/current");
        reqB.Headers.Add("X-Tenant-ID", tenantB.Id.ToString());
        var resB = await client1.SendAsync(reqB);
        Assert.Equal(HttpStatusCode.OK, resB.StatusCode);
        Assert.Equal(tenantB.Id, (await resB.Content.ReadFromJsonAsync<CurrentTenantContextResponse>())!.TenantId);

        var resNoHeader = await client1.GetAsync("/api/v1/tenancy/current");
        Assert.Equal(HttpStatusCode.BadRequest, resNoHeader.StatusCode);

        // 3. Parallel requests across User1 (Tenant A) and User2 (Tenant C) remain isolated
        var tasks = Enumerable.Range(0, 6).Select(async i =>
        {
            var isUser1 = i % 2 == 0;
            var targetClient = isUser1 ? client1 : client2;
            var expectedTenantId = isUser1 ? tenantA.Id : tenantC.Id;

            using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenancy/current");
            req.Headers.Add("X-Tenant-ID", expectedTenantId.ToString());
            var resp = await targetClient.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var ctx = await resp.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
            Assert.Equal(expectedTenantId, ctx!.TenantId);
        });
        await Task.WhenAll(tasks);
    }

    [Fact]
    public async Task Workflow4_MembershipRevocationAndTenantSuspension_AfterDiscovery()
    {
        var (client, user, _, _) = await CreateAuthenticatedUserAsync("wf4_user");
        var tenantA = await CreateActiveTenantWithOwnerAsync(client, "WF4 Org A");
        var tenantB = await CreateActiveTenantWithOwnerAsync(client, "WF4 Org B");

        // Scenario A: Revoke membership in Tenant A -> /current denied, /me excludes A, Tenant B unaffected
        using (var db = CreateDbContext())
        {
            using (db.CreatePrivilegedTenantBypassScope("wf4-revoke"))
            {
                var mem = await db.TenantMemberships.SingleAsync(m => m.TenantId == tenantA.Id && m.UserId == user.Id);
                mem.Revoke(DateTime.UtcNow);
                await db.SaveChangesAsync();
            }
        }

        using (var reqA = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenancy/current"))
        {
            reqA.Headers.Add("X-Tenant-ID", tenantA.Id.ToString());
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(reqA)).StatusCode);
        }

        var meAfterRevoke = await (await client.GetAsync("/api/v1/tenants/me"))
            .Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(meAfterRevoke);
        var onlyB = Assert.Single(meAfterRevoke);
        Assert.Equal(tenantB.Id, onlyB.TenantId);
        Assert.True(onlyB.IsSelectable);

        // Scenario B: Suspend Tenant B -> /current denied, /me shows IsSelectable == false
        using (var db = CreateDbContext())
        {
            var tB = await db.Tenants.SingleAsync(t => t.Id == tenantB.Id);
            tB.Suspend(DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        using (var reqB = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenancy/current"))
        {
            reqB.Headers.Add("X-Tenant-ID", tenantB.Id.ToString());
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(reqB)).StatusCode);
        }

        var meAfterSuspend = await (await client.GetAsync("/api/v1/tenants/me"))
            .Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(meAfterSuspend);
        var suspendedB = Assert.Single(meAfterSuspend);
        Assert.Equal("Suspended", suspendedB.TenantStatus);
        Assert.False(suspendedB.IsSelectable);

        // Scenario C: Re-invite into Tenant A -> new active membership returned while historical revoked row preserved
        using (var db = CreateDbContext())
        {
            using (db.CreatePrivilegedTenantBypassScope("wf4-reinvite"))
            {
                db.TenantMemberships.Add(TenantMembership.Create(
                    tenantA.Id,
                    user.Id,
                    TenantMembershipRole.Administrator,
                    TenantMembershipStatus.Active,
                    DateTime.UtcNow));
                await db.SaveChangesAsync();

                var totalRows = await db.TenantMemberships.CountAsync(m => m.TenantId == tenantA.Id && m.UserId == user.Id);
                Assert.Equal(2, totalRows);
            }
        }

        var meAfterReinvite = await (await client.GetAsync("/api/v1/tenants/me"))
            .Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(meAfterReinvite);
        var reinvitedA = meAfterReinvite.Single(m => m.TenantId == tenantA.Id);
        Assert.Equal("Administrator", reinvitedA.Role);
        Assert.True(reinvitedA.IsSelectable);
    }

    // =========================================================================
    // 4. OPENAPI / SWAGGER VERIFICATION
    // =========================================================================

    [Fact]
    public async Task OpenApi_SwaggerDocument_DocumentsCanonicalRoutesAndExcludesBlockedLifecycleRoutes()
    {
        var client = CreateClientForIp();
        var response = await client.GetAsync("/swagger/v1/swagger.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var paths = doc.RootElement.GetProperty("paths");

        Assert.True(paths.TryGetProperty("/api/v1/tenants", out var tenantsPath) && tenantsPath.TryGetProperty("post", out _));
        Assert.True(paths.TryGetProperty("/api/v1/tenants/me", out var mePath) && mePath.TryGetProperty("get", out _));
        Assert.True(paths.TryGetProperty("/api/v1/tenants/{id}", out var idPath)
                    && idPath.TryGetProperty("get", out _)
                    && idPath.TryGetProperty("patch", out _));
        Assert.True(paths.TryGetProperty("/api/v1/tenancy/current", out var currentPath) && currentPath.TryGetProperty("get", out _));

        // Blocked lifecycle endpoints must NOT be advertised
        Assert.False(paths.TryGetProperty("/api/v1/tenants/{id}/activate", out _));
        Assert.False(paths.TryGetProperty("/api/v1/tenants/{id}/suspend", out _));
        Assert.False(paths.TryGetProperty("/api/v1/tenants/{id}/deactivate", out _));

        // Security scheme Bearer present
        var securitySchemes = doc.RootElement.GetProperty("components").GetProperty("securitySchemes");
        Assert.True(securitySchemes.TryGetProperty("Bearer", out _));
    }
}
