namespace MaintenX.IntegrationTests;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
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
using Xunit;

/// <summary>
/// HTTP Integration tests for FEAT-003 Task 3.6.4 Tenant Lookup & Settings HTTP APIs
/// (GET /api/v1/tenants/{id} and PATCH /api/v1/tenants/{id}).
/// Covers lookup authorization, anti-enumeration, onboarding Location URI completion,
/// settings RBAC, route/header consistency, optimistic concurrency, mass-assignment defense,
/// durable settings audit persistence with transactional rollback, and blocked lifecycle routes.
/// </summary>
public class TenantSettingsHttpIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public TenantSettingsHttpIntegrationTests()
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

    private static int _ipCounter = 800;
    private HttpClient CreateUniqueClient()
    {
        var id = Interlocked.Increment(ref _ipCounter);
        var ip = $"198.51.{(id / 250) % 250}.{id % 250 + 1}";
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ip);
        return client;
    }

    private async Task<(HttpClient Client, User User, string Token, Guid SessionId)> CreateAuthenticatedUserAsync(string prefix = "settings_user")
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

    private async Task<TenantResponse> CreateActiveTenantWithOwnerAsync(HttpClient ownerClient, string displayName = "Acme Settings Org")
    {
        var slug = $"org-{Guid.NewGuid():N}"[..24];
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

    private async Task AddMemberAsync(Guid tenantId, Guid userId, TenantMembershipRole role, TenantMembershipStatus status = TenantMembershipStatus.Active)
    {
        using var db = CreateDbContext();
        using (db.CreatePrivilegedTenantBypassScope("seed-member"))
        {
            var membership = TenantMembership.Create(tenantId, userId, role, status, DateTime.UtcNow);
            db.TenantMemberships.Add(membership);
            await db.SaveChangesAsync();
        }
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
    // A. TENANT LOOKUP (GET /api/v1/tenants/{id})
    // =========================================================================

    [Fact]
    public async Task GetTenantById_AuthorizedOwnerAdministratorAndMember_Returns200WithMetadata()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("lookup_owner");
        var (adminClient, adminUser, _, _) = await CreateAuthenticatedUserAsync("lookup_admin");
        var (memberClient, memberUser, _, _) = await CreateAuthenticatedUserAsync("lookup_member");

        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Lookup Corp");
        await AddMemberAsync(tenant.Id, adminUser.Id, TenantMembershipRole.Administrator);
        await AddMemberAsync(tenant.Id, memberUser.Id, TenantMembershipRole.Member);

        foreach (var client in new[] { ownerClient, adminClient, memberClient })
        {
            var response = await client.GetAsync($"/api/v1/tenants/{tenant.Id}");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var body = await response.Content.ReadFromJsonAsync<TenantResponse>();
            Assert.NotNull(body);
            Assert.Equal(tenant.Id, body.Id);
            Assert.Equal(tenant.Slug, body.Slug);
            Assert.Equal("Lookup Corp", body.DisplayName);
            Assert.Equal("Active", body.Status);
            Assert.Equal(tenant.Version, body.Version);
        }
    }

    [Fact]
    public async Task GetTenantById_UnauthenticatedCaller_Returns401Unauthorized()
    {
        var client = CreateUniqueClient();
        var response = await client.GetAsync($"/api/v1/tenants/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetTenantById_RevokedSession_Returns401Unauthorized()
    {
        var (client, _, _, sessionId) = await CreateAuthenticatedUserAsync("lookup_rev_sess");
        var tenant = await CreateActiveTenantWithOwnerAsync(client, "Session Test Corp");

        using (var db = CreateDbContext())
        {
            var session = await db.UserSessions.FirstAsync(s => s.Id == sessionId);
            session.Revoke(SessionRevocationReason.AdminRevoked, DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        var response = await client.GetAsync($"/api/v1/tenants/{tenant.Id}");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetTenantById_ForeignAndNonexistentTenants_PreserveIdenticalAntiEnumeration404()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("anti_enum_owner");
        var (strangerClient, _, _, _) = await CreateAuthenticatedUserAsync("anti_enum_stranger");
        var foreignTenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Secret Foreign Org");

        var foreignResp = await strangerClient.GetAsync($"/api/v1/tenants/{foreignTenant.Id}");
        var missingResp = await strangerClient.GetAsync($"/api/v1/tenants/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreignResp.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missingResp.StatusCode);

        var foreignProblem = await foreignResp.Content.ReadFromJsonAsync<ProblemDetails>();
        var missingProblem = await missingResp.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(foreignProblem);
        Assert.NotNull(missingProblem);

        Assert.Equal(foreignProblem.Title, missingProblem.Title);
        Assert.Equal(foreignProblem.Detail, missingProblem.Detail);
        Assert.Equal(
            foreignProblem.Extensions["errorCode"]?.ToString(),
            missingProblem.Extensions["errorCode"]?.ToString());
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public async Task GetTenantById_InvalidTenantIdentifier_Returns400BadRequest(string invalidId)
    {
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("invalid_id_lookup");
        var response = await client.GetAsync($"/api/v1/tenants/{invalidId}");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task GetTenantById_PendingOnboardingOwner_FollowsLocationUri_WithoutActivatingOrEstablishingContext()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("onboard_loc_owner");
        var (otherClient, _, _, _) = await CreateAuthenticatedUserAsync("onboard_loc_other");

        var slug = $"loc-org-{Guid.NewGuid():N}"[..24];
        var createResp = await ownerClient.PostAsJsonAsync("/api/v1/tenants", new CreateTenantRequest(slug, "Location Org"));
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);
        Assert.NotNull(createResp.Headers.Location);

        // 1. Owner follows the returned Location URI
        var followResp = await ownerClient.GetAsync(createResp.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, followResp.StatusCode);

        var tenant = await followResp.Content.ReadFromJsonAsync<TenantResponse>();
        Assert.NotNull(tenant);
        Assert.Equal("PendingOnboarding", tenant.Status);

        // 2. Metadata lookup does NOT activate the tenant or establish operational context
        var currentWithoutHeader = await ownerClient.GetAsync("/api/v1/tenancy/current");
        Assert.Equal(HttpStatusCode.BadRequest, currentWithoutHeader.StatusCode);

        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());
        var currentPending = await ownerClient.GetAsync("/api/v1/tenancy/current");
        Assert.Equal(HttpStatusCode.Forbidden, currentPending.StatusCode);

        // 3. Unauthorized user cannot follow or read the PendingOnboarding tenant
        var otherResp = await otherClient.GetAsync(createResp.Headers.Location);
        Assert.Equal(HttpStatusCode.NotFound, otherResp.StatusCode);
    }

    // =========================================================================
    // B. SETTINGS AUTHORIZATION & ROUTE/HEADER CONSISTENCY (PATCH /api/v1/tenants/{id})
    // =========================================================================

    [Fact]
    public async Task PatchTenant_ActiveOwnerWithMatchingIdOrSlugHeader_UpdatesSettingsAndVersion()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("patch_owner");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Initial Name");

        // 1. Update with UUID in X-Tenant-ID
        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());
        var patch1 = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Updated Via UUID", tenant.Version));

        Assert.Equal(HttpStatusCode.OK, patch1.StatusCode);
        var updated1 = await patch1.Content.ReadFromJsonAsync<TenantResponse>();
        Assert.NotNull(updated1);
        Assert.Equal("Updated Via UUID", updated1.DisplayName);
        Assert.Equal(tenant.Version + 1, updated1.Version);

        // 2. Update with Slug in X-Tenant-ID
        ownerClient.DefaultRequestHeaders.Remove("X-Tenant-ID");
        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Slug);
        var patch2 = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Updated Via Slug", updated1.Version));

        Assert.Equal(HttpStatusCode.OK, patch2.StatusCode);
        var updated2 = await patch2.Content.ReadFromJsonAsync<TenantResponse>();
        Assert.NotNull(updated2);
        Assert.Equal("Updated Via Slug", updated2.DisplayName);
        Assert.Equal(updated1.Version + 1, updated2.Version);
    }

    [Fact]
    public async Task PatchTenant_ActiveAdministrator_UpdatesSettings()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("patch_adm_own");
        var (adminClient, adminUser, _, _) = await CreateAuthenticatedUserAsync("patch_adm");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Admin Test Org");
        await AddMemberAsync(tenant.Id, adminUser.Id, TenantMembershipRole.Administrator);

        adminClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());
        var response = await adminClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Admin Updated Org", tenant.Version));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var updated = await response.Content.ReadFromJsonAsync<TenantResponse>();
        Assert.NotNull(updated);
        Assert.Equal("Admin Updated Org", updated.DisplayName);
        Assert.Equal(tenant.Version + 1, updated.Version);
    }

    [Fact]
    public async Task PatchTenant_OrdinaryMember_Returns403Forbidden()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("patch_mem_own");
        var (memberClient, memberUser, _, _) = await CreateAuthenticatedUserAsync("patch_mem");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Member Blocked Org");
        await AddMemberAsync(tenant.Id, memberUser.Id, TenantMembershipRole.Member);

        memberClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());
        var response = await memberClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Member Hack", tenant.Version));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task PatchTenant_CrossTenantOwnerAndAdmin_DeniedWith403AndNoMutation()
    {
        var (ownerAClient, _, _, _) = await CreateAuthenticatedUserAsync("cross_owner_a");
        var (adminAClient, adminAUser, _, _) = await CreateAuthenticatedUserAsync("cross_admin_a");
        var (ownerBClient, _, _, _) = await CreateAuthenticatedUserAsync("cross_owner_b");

        var tenantA = await CreateActiveTenantWithOwnerAsync(ownerAClient, "Tenant A");
        await AddMemberAsync(tenantA.Id, adminAUser.Id, TenantMembershipRole.Administrator);
        var tenantB = await CreateActiveTenantWithOwnerAsync(ownerBClient, "Tenant B");

        // 1. Owner A with Tenant A header targeting Tenant B route (Route/Header mismatch)
        ownerAClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenantA.Id.ToString());
        var ownerMismatch = await ownerAClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenantB.Id}",
            new UpdateTenantRequest("Hijacked B", tenantB.Version));
        Assert.Equal(HttpStatusCode.Forbidden, ownerMismatch.StatusCode);

        // 2. Admin A with Tenant B header targeting Tenant B route (Not a member of Tenant B)
        adminAClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenantB.Id.ToString());
        var adminForeign = await adminAClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenantB.Id}",
            new UpdateTenantRequest("Hijacked B", tenantB.Version));
        Assert.Equal(HttpStatusCode.Forbidden, adminForeign.StatusCode);

        using var db = CreateDbContext();
        var persistedB = await db.Tenants.AsNoTracking().SingleAsync(t => t.Id == tenantB.Id);
        Assert.Equal("Tenant B", persistedB.DisplayName);
        Assert.Equal(tenantB.Version, persistedB.Version);
    }

    [Fact]
    public async Task PatchTenant_MissingOrInvalidTenantHeader_RejectedWithoutMutation()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("hdr_missing");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Header Required Org");

        // Missing X-Tenant-ID
        var missingResp = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Should Fail", tenant.Version));
        Assert.Equal(HttpStatusCode.BadRequest, missingResp.StatusCode);

        // Invalid nonexistent X-Tenant-ID
        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", Guid.NewGuid().ToString());
        var invalidResp = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Should Fail", tenant.Version));
        Assert.Equal(HttpStatusCode.NotFound, invalidResp.StatusCode);
    }

    [Fact]
    public async Task PatchTenant_SuspendedOrRevokedMembership_AndSuspendedOrDeactivatedTenant_Denied()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("state_owner");
        var (adminClient, adminUser, _, _) = await CreateAuthenticatedUserAsync("state_admin");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "State Policy Org");
        await AddMemberAsync(tenant.Id, adminUser.Id, TenantMembershipRole.Administrator);

        adminClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());
        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        // 1. Suspend admin membership -> 403
        using (var db = CreateDbContext())
        {
            using (db.CreatePrivilegedTenantBypassScope("suspend-admin"))
            {
                var mem = await db.TenantMemberships.SingleAsync(m => m.TenantId == tenant.Id && m.UserId == adminUser.Id);
                mem.Suspend(DateTime.UtcNow);
                await db.SaveChangesAsync();
            }
        }
        var suspendedMemResp = await adminClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Blocked Admin", tenant.Version));
        Assert.Equal(HttpStatusCode.Forbidden, suspendedMemResp.StatusCode);

        // 2. Suspend tenant -> 403
        using (var db = CreateDbContext())
        {
            var t = await db.Tenants.SingleAsync(x => x.Id == tenant.Id);
            t.Suspend(DateTime.UtcNow);
            await db.SaveChangesAsync();
        }
        var suspendedTenantResp = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Blocked Suspended", tenant.Version));
        Assert.Equal(HttpStatusCode.Forbidden, suspendedTenantResp.StatusCode);

        // 3. Deactivate tenant -> 403
        using (var db = CreateDbContext())
        {
            var t = await db.Tenants.SingleAsync(x => x.Id == tenant.Id);
            t.Deactivate(DateTime.UtcNow);
            await db.SaveChangesAsync();
        }
        var deactivatedTenantResp = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Blocked Deactivated", tenant.Version));
        Assert.Equal(HttpStatusCode.Forbidden, deactivatedTenantResp.StatusCode);
    }

    // =========================================================================
    // C. VALIDATION & MASS ASSIGNMENT
    // =========================================================================

    [Fact]
    public async Task PatchTenant_ValidationAndMalformedJson_Returns400BadRequest()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("val_owner");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Validation Org");
        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        // 1. Missing ExpectedVersion
        var missingVer = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new { displayName = "Valid Name" });
        Assert.Equal(HttpStatusCode.BadRequest, missingVer.StatusCode);

        // 2. Invalid ExpectedVersion (0 and -1)
        var zeroVer = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Valid Name", 0));
        Assert.Equal(HttpStatusCode.BadRequest, zeroVer.StatusCode);

        // 3. Invalid DisplayName (too short)
        var badName = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("A", tenant.Version));
        Assert.Equal(HttpStatusCode.BadRequest, badName.StatusCode);

        // 4. Malformed JSON
        var malformedContent = new StringContent("{ \"displayName\": \"Broken", Encoding.UTF8, "application/json");
        var malformedResp = await ownerClient.PatchAsync($"/api/v1/tenants/{tenant.Id}", malformedContent);
        Assert.Equal(HttpStatusCode.BadRequest, malformedResp.StatusCode);
    }

    [Fact]
    public async Task PatchTenant_MassAssignmentFields_IgnoredAndCannotElevatePrivileges()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("mass_owner");
        var (memberClient, memberUser, _, _) = await CreateAuthenticatedUserAsync("mass_member");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Mass Assign Org");
        await AddMemberAsync(tenant.Id, memberUser.Id, TenantMembershipRole.Member);

        // Owner sends extra immutable fields (id, slug, status, isPlatformAdmin)
        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());
        var ownerResp = await ownerClient.PatchAsJsonAsync($"/api/v1/tenants/{tenant.Id}", new
        {
            id = Guid.NewGuid(),
            slug = "hijacked-slug",
            status = "Deactivated",
            displayName = "Clean Name",
            expectedVersion = tenant.Version,
            isPlatformAdmin = true
        });
        Assert.Equal(HttpStatusCode.OK, ownerResp.StatusCode);
        var updated = await ownerResp.Content.ReadFromJsonAsync<TenantResponse>();
        Assert.NotNull(updated);
        Assert.Equal(tenant.Id, updated.Id);
        Assert.Equal(tenant.Slug, updated.Slug);
        Assert.Equal("Active", updated.Status);
        Assert.Equal("Clean Name", updated.DisplayName);

        // Member sends role="Owner", isPlatformAdmin=true -> still 403 Forbidden
        memberClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());
        var memberResp = await memberClient.PatchAsJsonAsync($"/api/v1/tenants/{tenant.Id}", new
        {
            displayName = "Escalated Name",
            expectedVersion = updated.Version,
            role = "Owner",
            isPlatformAdmin = true
        });
        Assert.Equal(HttpStatusCode.Forbidden, memberResp.StatusCode);
    }

    // =========================================================================
    // D. CONCURRENCY & IDEMPOTENCY
    // =========================================================================

    [Fact]
    public async Task PatchTenant_StaleVersionAndConcurrentUpdates_EnforceOptimisticConcurrency()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("conc_owner");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Concurrency Org");
        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        // 1. Concurrent competing updates with same initial ExpectedVersion
        var t1 = ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Winner Name", tenant.Version));
        var t2 = ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Loser Name", tenant.Version));

        var responses = await Task.WhenAll(t1, t2);
        var codes = responses.Select(r => r.StatusCode).ToList();
        Assert.Contains(HttpStatusCode.OK, codes);
        Assert.Contains(HttpStatusCode.Conflict, codes);

        var winner = await responses.First(r => r.StatusCode == HttpStatusCode.OK)
            .Content.ReadFromJsonAsync<TenantResponse>();
        Assert.NotNull(winner);
        Assert.Equal(tenant.Version + 1, winner.Version);

        // 2. Stale ExpectedVersion even with identical DisplayName -> 409 Conflict
        var staleSameName = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest(winner.DisplayName, tenant.Version));
        Assert.Equal(HttpStatusCode.Conflict, staleSameName.StatusCode);

        // 3. Matching ExpectedVersion with identical DisplayName -> 200 OK no-op (version unchanged)
        var noop = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest(winner.DisplayName, winner.Version));
        Assert.Equal(HttpStatusCode.OK, noop.StatusCode);
        var noopBody = await noop.Content.ReadFromJsonAsync<TenantResponse>();
        Assert.NotNull(noopBody);
        Assert.Equal(winner.Version, noopBody.Version);
    }

    // =========================================================================
    // E. DURABLE SETTINGS AUDIT, ROLLBACK & BLOCKED LIFECYCLE ROUTES
    // =========================================================================

    [Fact]
    public async Task PatchTenant_MeaningfulUpdatePersistsAuditEvent_NoOpAndRejectedProduceNone()
    {
        var (ownerClient, ownerUser, _, _) = await CreateAuthenticatedUserAsync("audit_owner");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Audit Org");
        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        // 1. Meaningful update -> emits 1 TenantSettingsUpdated audit event
        var okResp = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Audit Org Updated", tenant.Version));
        Assert.Equal(HttpStatusCode.OK, okResp.StatusCode);
        var updated = await okResp.Content.ReadFromJsonAsync<TenantResponse>();
        Assert.NotNull(updated);

        // 2. No-op update -> emits 0 new audit events
        var noopResp = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Audit Org Updated", updated.Version));
        Assert.Equal(HttpStatusCode.OK, noopResp.StatusCode);

        // 3. Stale rejected update -> emits 0 new audit events
        var conflictResp = await ownerClient.PatchAsJsonAsync(
            $"/api/v1/tenants/{tenant.Id}",
            new UpdateTenantRequest("Rejected Update", tenant.Version));
        Assert.Equal(HttpStatusCode.Conflict, conflictResp.StatusCode);

        using var db = CreateDbContext();
        var events = await db.TenantAuditEvents
            .AsNoTracking()
            .Where(e => e.TenantId == tenant.Id && e.Action == "TenantSettingsUpdated")
            .ToListAsync();

        var audit = Assert.Single(events);
        Assert.Equal(ownerUser.Id, audit.ActorUserId);
        Assert.Equal("Active", audit.PreviousStatus);
        Assert.Equal("Active", audit.NewStatus);
        Assert.Contains("DisplayName", audit.Reason);
    }

    [Fact]
    public async Task PatchTenant_AuditPersistenceFailure_RollsBackTenantMutation()
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync("audit_fail_owner");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Before Rollback");
        ownerClient.DefaultRequestHeaders.Add("X-Tenant-ID", tenant.Id.ToString());

        using (var db = CreateDbContext())
        {
            await db.Database.ExecuteSqlRawAsync(@"
                CREATE OR REPLACE FUNCTION platform.fail_settings_audit()
                RETURNS trigger AS $$
                BEGIN
                    IF NEW.action = 'TenantSettingsUpdated' THEN
                        RAISE EXCEPTION 'Simulated audit failure';
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;

                CREATE TRIGGER trg_fail_settings_audit
                BEFORE INSERT ON platform.tenant_audit_events
                FOR EACH ROW EXECUTE FUNCTION platform.fail_settings_audit();");
        }

        try
        {
            var resp = await ownerClient.PatchAsJsonAsync(
                $"/api/v1/tenants/{tenant.Id}",
                new UpdateTenantRequest("Should Rollback", tenant.Version));
            Assert.Equal(HttpStatusCode.InternalServerError, resp.StatusCode);

            using var verifyDb = CreateDbContext();
            var persisted = await verifyDb.Tenants.AsNoTracking().SingleAsync(t => t.Id == tenant.Id);
            Assert.Equal("Before Rollback", persisted.DisplayName);
            Assert.Equal(tenant.Version, persisted.Version);
        }
        finally
        {
            using var cleanupDb = CreateDbContext();
            await cleanupDb.Database.ExecuteSqlRawAsync(@"
                DROP TRIGGER IF EXISTS trg_fail_settings_audit ON platform.tenant_audit_events;
                DROP FUNCTION IF EXISTS platform.fail_settings_audit();");
        }
    }

    [Theory]
    [InlineData("activate")]
    [InlineData("suspend")]
    [InlineData("deactivate")]
    public async Task BlockedLifecycleEndpoints_RemainUnexposed(string action)
    {
        var (ownerClient, _, _, _) = await CreateAuthenticatedUserAsync($"blocked_{action}");
        var tenant = await CreateActiveTenantWithOwnerAsync(ownerClient, "Lifecycle Blocked Org");

        var resp = await ownerClient.PostAsync($"/api/v1/tenants/{tenant.Id}/{action}", null);
        Assert.True(
            resp.StatusCode == HttpStatusCode.NotFound || resp.StatusCode == HttpStatusCode.MethodNotAllowed,
            $"Expected 404 or 405 for blocked lifecycle route /{action}, got {resp.StatusCode}.");
    }
}
