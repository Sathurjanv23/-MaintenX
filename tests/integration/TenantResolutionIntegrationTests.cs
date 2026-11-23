namespace MaintenX.IntegrationTests;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

/// <summary>
/// Comprehensive integration test suite for FEAT-003 Step 3.3 Tenant Context & Membership Resolution.
/// Runs against a disposable, isolated PostgreSQL 16 database.
/// Validates server-side membership resolution, active tenant lifecycle enforcement,
/// cross-tenant isolation, explicit selection, and failure handling.
/// </summary>
public class TenantResolutionIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public TenantResolutionIntegrationTests()
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

    private static int _ipCounter = 200;
    private HttpClient CreateUniqueClient()
    {
        var id = Interlocked.Increment(ref _ipCounter);
        var ip = $"198.51.{(id / 250) % 250}.{id % 250 + 1}";
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ip);
        return client;
    }

    private async Task<(HttpClient Client, User User, string Token)> CreateAuthenticatedUserAsync(string prefix = "user")
    {
        var client = CreateUniqueClient();
        var email = $"{prefix}_{Guid.NewGuid():N}@maintenx.internal";
        var password = "SecurePassword123!";

        var regResp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, regResp.StatusCode);

        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);

        var body = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(body);

        using var db = CreateDbContext();
        var user = await db.Users.FirstAsync(u => u.Email == email);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.AccessToken);
        return (client, user, body.AccessToken);
    }

    private async Task<Tenant> CreateTenantAsync(string slug, string displayName, TenantStatus status = TenantStatus.Active)
    {
        using var db = CreateDbContext();
        var tenant = Tenant.Create(slug, displayName, status);
        db.Tenants.Add(tenant);
        await db.SaveChangesAsync();
        return tenant;
    }

    private async Task<TenantMembership> AddMembershipAsync(
        Guid tenantId,
        Guid userId,
        TenantMembershipRole role,
        TenantMembershipStatus status = TenantMembershipStatus.Active)
    {
        using var db = CreateDbContext();
        var membership = TenantMembership.Create(tenantId, userId, role, status);
        db.TenantMemberships.Add(membership);
        await db.SaveChangesAsync();
        return membership;
    }

    // =========================================================================
    // 1. SUCCESSFUL RESOLUTION TESTS
    // =========================================================================

    [Fact]
    public async Task Resolve_ValidActiveMembership_ByTenantIdHeader_Returns200WithContext()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("res_id");
        var tenant = await CreateTenantAsync($"tenant-{Guid.NewGuid():N}"[..20], "Acme Facility Services");
        var membership = await AddMembershipAsync(tenant.Id, user.Id, TenantMembershipRole.Owner);

        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.NotNull(body);
        Assert.Equal(tenant.Id, body.TenantId);
        Assert.Equal(tenant.Slug, body.TenantSlug);
        Assert.Equal(tenant.DisplayName, body.TenantDisplayName);
        Assert.Equal(user.Id, body.UserId);
        Assert.Equal(membership.Id, body.MembershipId);
        Assert.Equal("Owner", body.Role);
        Assert.Equal("Active", body.Status);
    }

    [Fact]
    public async Task Resolve_ValidActiveMembership_ByTenantSlugHeader_Returns200WithContext()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("res_slug");
        var slug = $"slug-{Guid.NewGuid():N}"[..20];
        var tenant = await CreateTenantAsync(slug, "Slug Facility Management");
        var membership = await AddMembershipAsync(tenant.Id, user.Id, TenantMembershipRole.Administrator);

        client.DefaultRequestHeaders.Add("X-Tenant-ID", slug.ToUpperInvariant()); // Verifies case-insensitive slug lookup

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.NotNull(body);
        Assert.Equal(tenant.Id, body.TenantId);
        Assert.Equal(tenant.Slug, body.TenantSlug);
        Assert.Equal(membership.Id, body.MembershipId);
        Assert.Equal("Administrator", body.Role);
    }

    [Fact]
    public async Task Resolve_UserWithMultipleMemberships_ResolvesExplicitlyRequestedTenant_NoImplicitDefault()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("multi_mem");

        var tenantA = await CreateTenantAsync($"tenant-a-{Guid.NewGuid():N}"[..20], "Tenant Alpha");
        var tenantB = await CreateTenantAsync($"tenant-b-{Guid.NewGuid():N}"[..20], "Tenant Beta");

        var memA = await AddMembershipAsync(tenantA.Id, user.Id, TenantMembershipRole.Owner);
        var memB = await AddMembershipAsync(tenantB.Id, user.Id, TenantMembershipRole.Member);

        // Request Tenant A
        client.DefaultRequestHeaders.Remove("X-Tenant-ID");
        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenantA.Id.ToString());
        var respA = await client.GetAsync("/api/v1/tenancy/current");
        Assert.Equal(HttpStatusCode.OK, respA.StatusCode);
        var bodyA = await respA.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.Equal(tenantA.Id, bodyA!.TenantId);
        Assert.Equal(memA.Id, bodyA.MembershipId);
        Assert.Equal("Owner", bodyA.Role);

        // Request Tenant B
        client.DefaultRequestHeaders.Remove("X-Tenant-ID");
        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenantB.Id.ToString());
        var respB = await client.GetAsync("/api/v1/tenancy/current");
        Assert.Equal(HttpStatusCode.OK, respB.StatusCode);
        var bodyB = await respB.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.Equal(tenantB.Id, bodyB!.TenantId);
        Assert.Equal(memB.Id, bodyB.MembershipId);
        Assert.Equal("Member", bodyB.Role);
    }

    // =========================================================================
    // 2. ERROR & SECURITY HANDLING TESTS
    // =========================================================================

    [Fact]
    public async Task Resolve_MissingTenantHeader_Returns400BadRequest()
    {
        var (client, _, _) = await CreateAuthenticatedUserAsync("no_header");

        // No X-Tenant-ID header provided
        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(400, doc.RootElement.GetProperty("status").GetInt32());
        Assert.Contains("X-Tenant-ID", doc.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Resolve_NonExistentTenant_Returns404NotFound_AvoidsEnumeration()
    {
        var (client, _, _) = await CreateAuthenticatedUserAsync("non_exist");

        client.DefaultRequestHeaders.Add("X-Tenant-ID", Guid.NewGuid().ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(404, doc.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task Resolve_UserHasNoMembershipInTenant_Returns403Forbidden()
    {
        var (client, _, _) = await CreateAuthenticatedUserAsync("no_mem");
        var tenant = await CreateTenantAsync($"tenant-{Guid.NewGuid():N}"[..20], "Foreign Org");

        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(403, doc.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task Resolve_PendingMembership_Returns403Forbidden()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("pending_mem");
        var tenant = await CreateTenantAsync($"tenant-{Guid.NewGuid():N}"[..20], "Pending Org");
        await AddMembershipAsync(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Pending);

        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Contains("pending", doc.RootElement.GetProperty("detail").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Resolve_SuspendedMembership_Returns403Forbidden()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("susp_mem");
        var tenant = await CreateTenantAsync($"tenant-{Guid.NewGuid():N}"[..20], "Suspended Mem Org");
        await AddMembershipAsync(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Suspended);

        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Contains("suspended", doc.RootElement.GetProperty("detail").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Resolve_RevokedMembership_Returns403Forbidden()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("rev_mem");
        var tenant = await CreateTenantAsync($"tenant-{Guid.NewGuid():N}"[..20], "Revoked Mem Org");

        // Revoked membership
        using (var db = CreateDbContext())
        {
            var m = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member);
            m.Revoke(DateTime.UtcNow);
            db.TenantMemberships.Add(m);
            await db.SaveChangesAsync();
        }

        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Contains("revoked", doc.RootElement.GetProperty("detail").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Resolve_SuspendedTenant_Returns403Forbidden()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("susp_tenant");
        var tenant = await CreateTenantAsync($"tenant-{Guid.NewGuid():N}"[..20], "Suspended Org", TenantStatus.Suspended);
        await AddMembershipAsync(tenant.Id, user.Id, TenantMembershipRole.Owner);

        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Contains("suspended", doc.RootElement.GetProperty("detail").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Resolve_DeactivatedTenant_Returns403Forbidden()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("deact_tenant");
        var tenant = await CreateTenantAsync($"tenant-{Guid.NewGuid():N}"[..20], "Deactivated Org", TenantStatus.Deactivated);
        await AddMembershipAsync(tenant.Id, user.Id, TenantMembershipRole.Owner);

        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Contains("deactivated", doc.RootElement.GetProperty("detail").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Resolve_PendingOnboardingTenant_Returns403Forbidden()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("onboard_tenant");
        var tenant = await CreateTenantAsync($"tenant-{Guid.NewGuid():N}"[..20], "Onboarding Org", TenantStatus.PendingOnboarding);
        await AddMembershipAsync(tenant.Id, user.Id, TenantMembershipRole.Owner);

        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Contains("onboarding", doc.RootElement.GetProperty("detail").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Resolve_Unauthenticated_Returns401Unauthorized()
    {
        var client = CreateUniqueClient();
        client.DefaultRequestHeaders.Add("X-Tenant-ID", Guid.NewGuid().ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Resolve_RevokedSession_Returns401Unauthorized()
    {
        var (client, user, _) = await CreateAuthenticatedUserAsync("rev_session");
        var tenant = await CreateTenantAsync($"tenant-{Guid.NewGuid():N}"[..20], "Session Test Org");
        await AddMembershipAsync(tenant.Id, user.Id, TenantMembershipRole.Owner);

        // Revoke the user's active session in the database
        using (var db = CreateDbContext())
        {
            var session = await db.UserSessions.FirstAsync(s => s.UserId == user.Id);
            session.Revoke("AdminRevoked", DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // =========================================================================
    // 3. PIPELINE COMPATIBILITY & CONCURRENCY TESTS
    // =========================================================================

    [Fact]
    public async Task AnonymousEndpoint_WorksWithoutTenantHeader()
    {
        var client = CreateUniqueClient();

        var healthResp = await client.GetAsync("/health/live");
        Assert.Equal(HttpStatusCode.OK, healthResp.StatusCode);

        var infoResp = await client.GetAsync("/api/v1/info");
        Assert.Equal(HttpStatusCode.OK, infoResp.StatusCode);
    }

    [Fact]
    public async Task TenantNeutralAuthenticatedEndpoint_WorksWithoutTenantHeader()
    {
        var (client, _, _) = await CreateAuthenticatedUserAsync("neutral_auth");

        // Change password endpoint is authenticated but tenant-neutral; should not require X-Tenant-ID
        var response = await client.PostAsJsonAsync("/api/v1/auth/change-password", new ChangePasswordRequest(
            "SecurePassword123!",
            "NewSecurePassword456!"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ConcurrentRequests_WithDifferentTenants_DoNotLeakContext()
    {
        var (client, user, token) = await CreateAuthenticatedUserAsync("concurrent_tenants");

        var tenant1 = await CreateTenantAsync($"tenant-c1-{Guid.NewGuid():N}"[..20], "Concurrent Org 1");
        var tenant2 = await CreateTenantAsync($"tenant-c2-{Guid.NewGuid():N}"[..20], "Concurrent Org 2");

        var mem1 = await AddMembershipAsync(tenant1.Id, user.Id, TenantMembershipRole.Owner);
        var mem2 = await AddMembershipAsync(tenant2.Id, user.Id, TenantMembershipRole.Member);

        // Execute 20 concurrent requests interleaved across both tenants
        var tasks = Enumerable.Range(0, 20).Select(async i =>
        {
            var isTenant1 = i % 2 == 0;
            var targetTenant = isTenant1 ? tenant1 : tenant2;
            var expectedMem = isTenant1 ? mem1 : mem2;
            var expectedRole = isTenant1 ? "Owner" : "Member";

            var reqClient = CreateUniqueClient();
            reqClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            reqClient.DefaultRequestHeaders.Add("X-Tenant-ID", targetTenant.Id.ToString());

            var resp = await reqClient.GetAsync("/api/v1/tenancy/current");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

            var body = await resp.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
            Assert.NotNull(body);
            Assert.Equal(targetTenant.Id, body.TenantId);
            Assert.Equal(expectedMem.Id, body.MembershipId);
            Assert.Equal(expectedRole, body.Role);
        });

        await Task.WhenAll(tasks);
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
