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
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

/// <summary>
/// HTTP Integration tests for FEAT-003 Task 3.6.3 Membership Discovery & Workspace Selection APIs (GET /api/v1/tenants/me).
/// Validates authenticated caller workspace discovery, deterministic ordering (TenantDisplayName asc, TenantId asc),
/// zero-membership handling, operation without X-Tenant-ID, strict cross-tenant isolation and anti-leakage,
/// session revocation enforcement, non-disclosure/anti-enumeration, and server-side computed IsSelectable flags.
/// </summary>
public class TenantMembershipHttpIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public TenantMembershipHttpIntegrationTests()
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

    private static int _ipCounter = 600;
    private HttpClient CreateUniqueClient()
    {
        var id = Interlocked.Increment(ref _ipCounter);
        var ip = $"198.51.{(id / 250) % 250}.{id % 250 + 1}";
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ip);
        return client;
    }

    private async Task<(HttpClient Client, User User, string Token, Guid SessionId)> CreateAuthenticatedUserAsync(string prefix = "mem_user")
    {
        var client = CreateUniqueClient();
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
    // 1. SUCCESSFUL MEMBERSHIP DISCOVERY WORKFLOWS
    // =========================================================================

    [Fact]
    public async Task GetUserMemberships_AuthenticatedUserWithActiveMembership_Returns200WithMembershipDetails()
    {
        // Arrange: create user and an onboarded tenant (which creates Owner membership)
        var (client, user, _, _) = await CreateAuthenticatedUserAsync("active_disc");
        var slug = $"org-{Guid.NewGuid():N}"[..24];
        var createResponse = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, "Alpha Org"));
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        var created = await createResponse.Content.ReadFromJsonAsync<CreateTenantResponse>();
        Assert.NotNull(created);

        // Transition tenant to Active in DB so IsSelectable becomes true
        using (var db = CreateDbContext())
        {
            var tenant = await db.Tenants.SingleAsync(t => t.Id == created.TenantId);
            tenant.Activate(DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        // Act: Call GET /api/v1/tenants/me (without X-Tenant-ID header)
        var response = await client.GetAsync("/api/v1/tenants/me");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(list);
        var membership = Assert.Single(list);

        Assert.Equal(created.TenantId, membership.TenantId);
        Assert.Equal(slug, membership.TenantSlug);
        Assert.Equal("Alpha Org", membership.TenantDisplayName);
        Assert.Equal("Owner", membership.Role);
        Assert.Equal("Active", membership.Status);
        Assert.Equal("Active", membership.TenantStatus);
        Assert.True(membership.IsSelectable);
        Assert.NotEqual(Guid.Empty, membership.MembershipId);
    }

    [Fact]
    public async Task GetUserMemberships_MultipleOrganizations_ReturnsAllMembershipsWithDeterministicOrdering()
    {
        // Arrange
        var (client, user, _, _) = await CreateAuthenticatedUserAsync("multi_org");

        // Create 3 tenants with deliberate names: "Zeta Facilities", "Beta Logistics", "Alpha Industries"
        var slug1 = $"zeta-{Guid.NewGuid():N}"[..24];
        var slug2 = $"beta-{Guid.NewGuid():N}"[..24];
        var slug3 = $"alpha-{Guid.NewGuid():N}"[..24];

        var t1 = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug1, "Zeta Facilities"));
        var t2 = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug2, "Beta Logistics"));
        var t3 = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug3, "Alpha Industries"));
        Assert.Equal(HttpStatusCode.Created, t1.StatusCode);
        Assert.Equal(HttpStatusCode.Created, t2.StatusCode);
        Assert.Equal(HttpStatusCode.Created, t3.StatusCode);

        // Act
        var response = await client.GetAsync("/api/v1/tenants/me");

        // Assert: 200 OK and ordered alphabetically by TenantDisplayName ("Alpha", "Beta", "Zeta")
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(list);
        Assert.Equal(3, list.Count);

        Assert.Equal("Alpha Industries", list[0].TenantDisplayName);
        Assert.Equal("Beta Logistics", list[1].TenantDisplayName);
        Assert.Equal("Zeta Facilities", list[2].TenantDisplayName);
    }

    [Fact]
    public async Task GetUserMemberships_UserWithNoMemberships_Returns200WithEmptyArray()
    {
        // Arrange: User registered and logged in, but not added to any tenant
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("zero_mems");

        // Act
        var response = await client.GetAsync("/api/v1/tenants/me");

        // Assert: 200 OK with empty array []
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(list);
        Assert.Empty(list);
    }

    [Fact]
    public async Task GetUserMemberships_WithoutTenantHeader_Succeeds()
    {
        // Arrange: User with a tenant membership
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("no_header");
        var slug = $"nohead-{Guid.NewGuid():N}"[..24];
        var createResp = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, "No Header Corp"));
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);

        // Ensure X-Tenant-ID header is NOT present on client
        Assert.False(client.DefaultRequestHeaders.Contains("X-Tenant-ID"));

        // Act
        var response = await client.GetAsync("/api/v1/tenants/me");

        // Assert: 200 OK
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(list);
        Assert.Single(list);
    }

    // =========================================================================
    // 2. TENANT ISOLATION & CROSS-TENANT DATA PROTECTION
    // =========================================================================

    [Fact]
    public async Task GetUserMemberships_WithArbitraryForeignTenantHeader_DoesNotFilterOrDiscloseForeignData()
    {
        // Arrange: User A creates Tenant A, User B creates Tenant B
        var (clientA, userA, _, _) = await CreateAuthenticatedUserAsync("user_a");
        var (clientB, userB, _, _) = await CreateAuthenticatedUserAsync("user_b");

        var slugA = $"slug-a-{Guid.NewGuid():N}"[..24];
        var slugB = $"slug-b-{Guid.NewGuid():N}"[..24];

        var respA = await clientA.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slugA, "Tenant A"));
        var respB = await clientB.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slugB, "Tenant B"));
        var bodyA = await respA.Content.ReadFromJsonAsync<CreateTenantResponse>();
        var bodyB = await respB.Content.ReadFromJsonAsync<CreateTenantResponse>();

        // Act: User A supplies Tenant B's ID in X-Tenant-ID header
        clientA.DefaultRequestHeaders.Add("X-Tenant-ID", bodyB!.TenantId.ToString());
        var response = await clientA.GetAsync("/api/v1/tenants/me");

        // Assert:
        // Because GET /api/v1/tenants/me resolves actor with requireActiveTenantContext: false,
        // it discovers userA's own memberships, ignoring the irrelevant header and NEVER leaking Tenant B!
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(list);
        var item = Assert.Single(list);
        Assert.Equal(bodyA!.TenantId, item.TenantId);
        Assert.NotEqual(bodyB.TenantId, item.TenantId);
    }

    // =========================================================================
    // 3. WORKSPACE ELIGIBILITY (IsSelectable) EVALUATION
    // =========================================================================

    [Fact]
    public async Task GetUserMemberships_PendingOnboardingTenant_IsSelectableIsFalse()
    {
        // Arrange: Newly created tenant is PendingOnboarding by default
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("pending_sel");
        var slug = $"pend-sel-{Guid.NewGuid():N}"[..24];
        var createResp = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, "Pending Org"));
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);

        // Act
        var response = await client.GetAsync("/api/v1/tenants/me");

        // Assert: TenantStatus == "PendingOnboarding", IsSelectable == false
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(list);
        var item = Assert.Single(list);
        Assert.Equal("PendingOnboarding", item.TenantStatus);
        Assert.Equal("Active", item.Status);
        Assert.False(item.IsSelectable);
    }

    [Fact]
    public async Task GetUserMemberships_SuspendedTenant_IsSelectableIsFalse()
    {
        // Arrange
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("susp_sel");
        var slug = $"susp-sel-{Guid.NewGuid():N}"[..24];
        var createResp = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, "Suspended Org"));
        var created = await createResp.Content.ReadFromJsonAsync<CreateTenantResponse>();

        // Suspend the tenant in DB
        using (var db = CreateDbContext())
        {
            var now = DateTime.UtcNow;
            var tenant = await db.Tenants.SingleAsync(t => t.Id == created!.TenantId);
            tenant.Activate(now); // first active
            tenant.Suspend(now.AddSeconds(1));  // then suspended
            await db.SaveChangesAsync();
        }

        // Act
        var response = await client.GetAsync("/api/v1/tenants/me");

        // Assert: TenantStatus == "Suspended", IsSelectable == false
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(list);
        var item = Assert.Single(list);
        Assert.Equal("Suspended", item.TenantStatus);
        Assert.False(item.IsSelectable);
    }

    [Fact]
    public async Task GetUserMemberships_RevokedMembership_IsExcludedFromResults()
    {
        // Arrange: Create tenant and member
        var (client, user, _, _) = await CreateAuthenticatedUserAsync("rev_disc");
        var slug = $"rev-disc-{Guid.NewGuid():N}"[..24];
        var createResp = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, "Revoked Org"));
        var created = await createResp.Content.ReadFromJsonAsync<CreateTenantResponse>();

        // Revoke the membership in DB
        using (var db = CreateDbContext())
        {
            using (db.CreatePrivilegedTenantBypassScope("revoke-membership"))
            {
                var membership = await db.TenantMemberships
                    .SingleAsync(m => m.TenantId == created!.TenantId && m.UserId == user.Id);
                membership.Revoke(DateTime.UtcNow);
                await db.SaveChangesAsync();
            }
        }

        // Act
        var response = await client.GetAsync("/api/v1/tenants/me");

        // Assert: 200 OK with empty array (revoked memberships are excluded from discovery)
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(list);
        Assert.Empty(list);
    }

    [Fact]
    public async Task GetUserMemberships_ReinvitedMembership_ReturnsCurrentActiveRecord()
    {
        // Arrange
        var (client, user, _, _) = await CreateAuthenticatedUserAsync("reinv_disc");
        var slug = $"reinv-{Guid.NewGuid():N}"[..24];
        var createResp = await client.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, "Reinvited Org"));
        var created = await createResp.Content.ReadFromJsonAsync<CreateTenantResponse>();

        // Revoke old membership and create a new active membership (simulating re-invitation)
        using (var db = CreateDbContext())
        {
            var now = DateTime.UtcNow;
            var tenant = await db.Tenants.SingleAsync(t => t.Id == created!.TenantId);
            tenant.Activate(now);

            using (db.CreatePrivilegedTenantBypassScope("reinvite-membership"))
            {
                var oldMembership = await db.TenantMemberships
                    .SingleAsync(m => m.TenantId == tenant.Id && m.UserId == user.Id);
                oldMembership.Revoke(now);

                var newMembership = TenantMembership.Create(
                    tenant.Id,
                    user.Id,
                    TenantMembershipRole.Member,
                    TenantMembershipStatus.Active,
                    now.AddSeconds(1));
                db.TenantMemberships.Add(newMembership);

                await db.SaveChangesAsync();
            }
        }

        // Act
        var response = await client.GetAsync("/api/v1/tenants/me");

        // Assert: Exactly ONE active membership returned with role Member, IsSelectable true
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserTenantMembershipResponse>>();
        Assert.NotNull(list);
        var item = Assert.Single(list);
        Assert.Equal("Member", item.Role);
        Assert.Equal("Active", item.Status);
        Assert.Equal("Active", item.TenantStatus);
        Assert.True(item.IsSelectable);
    }

    // =========================================================================
    // 4. AUTHENTICATION & SECURITY ENFORCEMENT
    // =========================================================================

    [Fact]
    public async Task GetUserMemberships_UnauthenticatedCaller_Returns401Unauthorized()
    {
        var client = CreateUniqueClient(); // No auth header

        var response = await client.GetAsync("/api/v1/tenants/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetUserMemberships_RevokedSession_Returns401Unauthorized()
    {
        // Arrange: Valid user, then session is revoked
        var (client, _, _, sessionId) = await CreateAuthenticatedUserAsync("revoked_session");

        using (var db = CreateDbContext())
        {
            var session = await db.UserSessions.FirstAsync(s => s.Id == sessionId);
            session.Revoke(SessionRevocationReason.AdminRevoked, DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        // Act
        var response = await client.GetAsync("/api/v1/tenants/me");

        // Assert: 401 Unauthorized
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
