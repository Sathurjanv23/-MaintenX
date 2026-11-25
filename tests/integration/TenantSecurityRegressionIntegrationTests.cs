namespace MaintenX.IntegrationTests;

using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Models;
using MaintenX.Api.Application.Tenancy.Services;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

/// <summary>
/// Comprehensive integration regression test suite for FEAT-003 Task 3.5.5
/// Security Regression &amp; Final Application Service Verification.
/// Executes against a disposable, isolated PostgreSQL 16 database.
/// Validates the 7 mandatory end-to-end multi-tenant application service workflows:
/// 1. New Organization Onboarding (PendingOnboarding status, Owner atomicity, neutral discovery allowed, context access blocked)
/// 2. Authorized Lifecycle Transition (Test admin activation, durable audit trail, context established)
/// 3. Multiple Organizations (Neutral discovery ordering, workspace isolation)
/// 4. Unauthorized Cross-Tenant Access (Rejection without data disclosure, anti-enumeration)
/// 5. Tenant Suspension (Durable audit, context blocked, unaffected tenants remain accessible)
/// 6. Audit Failure Rollback (Atomic failure rollback: status and version unmutated, zero orphan audit records)
/// 7. Revoked Membership &amp; Re-invitation (Historical preservation, current active membership resolution)
/// </summary>
public class TenantSecurityRegressionIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public TenantSecurityRegressionIntegrationTests()
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
        _factory?.Dispose();

        if (!string.IsNullOrWhiteSpace(_databaseName))
        {
            await TestDatabaseGuard.DropDatabaseSafelyAsync(_databaseName, _adminConnectionString);
        }
    }

    private MaintenXDbContext CreateContext(IInterceptor? interceptor = null)
    {
        var optionsBuilder = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString);

        if (interceptor != null)
        {
            optionsBuilder.AddInterceptors(interceptor);
        }

        return new MaintenXDbContext(optionsBuilder.Options);
    }

    private static int _ipCounter = 300;
    private HttpClient CreateUniqueClient()
    {
        var id = Interlocked.Increment(ref _ipCounter);
        var ip = $"198.51.{(id / 250) % 250}.{id % 250 + 1}";
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ip);
        return client;
    }

    private async Task<(HttpClient Client, User User, string Token)> CreateAuthenticatedUserAsync(string prefix = "reg_user")
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

        using var db = CreateContext();
        var user = await db.Users.FirstAsync(u => u.Email == email);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.AccessToken);
        return (client, user, body.AccessToken);
    }

    private TenantService CreateTenantService(MaintenXDbContext context)
    {
        return new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
    }

    private TenantMembershipService CreateMembershipService(MaintenXDbContext context)
    {
        return new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
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

    #region Workflow 1: New Organization Onboarding

    [Fact]
    public async Task Workflow1_NewOrganizationOnboarding_PendingStatus_OwnerAtomic_DiscoveryAllowed_AccessBlocked()
    {
        // Arrange
        var (client, user, _) = await CreateAuthenticatedUserAsync("wf1_user");
        var userActor = TenantActorContext.FromUser(user.Id);

        string slug = $"acme-onboard-{Guid.NewGuid():N}"[..24];
        var request = new CreateTenantRequest(
            Slug: slug,
            DisplayName: "Acme Onboarding Corp");

        CreateTenantResult createResult;

        // Act: 1. Create tenant via TenantService
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            createResult = await tenantService.CreateTenantAsync(user.Id, request);
        }

        // Assert: 1. Verify tenant is created in PendingOnboarding status with Owner membership
        Assert.True(createResult.IsSuccess);
        Assert.Equal(201, createResult.StatusCode);
        Assert.NotNull(createResult.Response);
        Assert.Equal(slug, createResult.Response.Slug);
        Assert.Equal("PendingOnboarding", createResult.Response.Status);

        var tenantId = createResult.Response.TenantId;

        using (var verifyContext = CreateContext())
        {
            var dbTenant = await verifyContext.Tenants.AsNoTracking().SingleOrDefaultAsync(t => t.Id == tenantId);
            Assert.NotNull(dbTenant);
            Assert.Equal(TenantStatus.PendingOnboarding, dbTenant.Status);

            using (verifyContext.CreatePrivilegedTenantBypassScope("verify-owner-membership"))
            {
                var membership = await verifyContext.TenantMemberships
                    .AsNoTracking()
                    .SingleOrDefaultAsync(m => m.TenantId == tenantId && m.UserId == user.Id);

                Assert.NotNull(membership);
                Assert.Equal(TenantMembershipRole.Owner, membership.Role);
                Assert.Equal(TenantMembershipStatus.Active, membership.Status);
            }
        }

        // Act & Assert: 2. Tenant-neutral discovery via TenantMembershipService shows organization
        using (var context = CreateContext())
        {
            var membershipService = CreateMembershipService(context);
            var discoveryResult = await membershipService.GetUserMembershipsAsync(user.Id, userActor);

            Assert.NotNull(discoveryResult);
            var found = Assert.Single(discoveryResult, m => m.TenantId == tenantId);
            Assert.Equal("Acme Onboarding Corp", found.TenantDisplayName);
            Assert.Equal("Owner", found.Role);
            Assert.Equal("Active", found.Status);
        }

        // Act & Assert: 3. Tenant resolution HTTP endpoint rejects operational context resolution for PendingOnboarding tenant (403 Forbidden)
        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenantId.ToString());
        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Access to the requested tenant organization is denied.", doc.RootElement.GetProperty("detail").GetString());
    }

    #endregion

    #region Workflow 2: Authorized Lifecycle Transition

    [Fact]
    public async Task Workflow2_AuthorizedLifecycleTransition_Activation_DurableAudit_ContextEstablished()
    {
        // Arrange
        var (client, owner, _) = await CreateAuthenticatedUserAsync("wf2_owner");
        var adminUser = (await CreateAuthenticatedUserAsync("wf2_platform_admin")).User;

        var ownerActor = TenantActorContext.FromUser(owner.Id);
        var adminActor = TenantActorContext.PlatformAdmin(adminUser.Id);

        string slug = $"wf2-active-{Guid.NewGuid():N}"[..24];
        CreateTenantResult createResult;
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            createResult = await tenantService.CreateTenantAsync(
                owner.Id,
                new CreateTenantRequest(slug, "Workflow 2 Enterprise"));
        }

        var tenantId = createResult.Response!.TenantId;

        // Act: 1. Transition tenant from PendingOnboarding to Active via authorized actor
        TenantLifecycleResult activatedResult;
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            activatedResult = await tenantService.ActivateTenantAsync(tenantId, adminActor);
        }

        // Assert: 1. Status updated to Active
        Assert.True(activatedResult.IsSuccess);
        Assert.Equal(200, activatedResult.StatusCode);
        Assert.NotNull(activatedResult.Response);
        Assert.Equal("Active", activatedResult.Response.Status);

        // Assert: 2. Durable audit event exists in platform.tenant_audit_events
        using (var verifyContext = CreateContext())
        {
            var dbTenant = await verifyContext.Tenants.AsNoTracking().SingleAsync(t => t.Id == tenantId);
            Assert.Equal(TenantStatus.Active, dbTenant.Status);

            var auditEvents = await verifyContext.TenantAuditEvents
                .AsNoTracking()
                .Where(a => a.TenantId == tenantId)
                .ToListAsync();

            Assert.Single(auditEvents);
            var audit = auditEvents[0];
            Assert.Equal("TenantActivated", audit.Action);
            Assert.Equal(adminUser.Id, audit.ActorUserId);
            Assert.Equal("PendingOnboarding", audit.PreviousStatus);
            Assert.Equal("Active", audit.NewStatus);
        }

        // Act & Assert: 3. Tenant resolution HTTP endpoint now resolves active tenant context successfully (200 OK)
        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenantId.ToString());
        var response = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.NotNull(body);
        Assert.Equal(tenantId, body.TenantId);
        Assert.Equal(slug, body.TenantSlug);
        Assert.Equal(owner.Id, body.UserId);
        Assert.Equal("Owner", body.Role);
        Assert.Equal("Active", body.Status);
    }

    #endregion

    #region Workflow 3: Multiple Organizations

    [Fact]
    public async Task Workflow3_MultipleOrganizations_DeterministicDiscovery_StrictIsolation()
    {
        // Arrange
        var (client, user, _) = await CreateAuthenticatedUserAsync("wf3_multi");
        var userActor = TenantActorContext.FromUser(user.Id);
        var adminActor = TenantActorContext.PlatformAdmin(Guid.NewGuid());

        // Create Organization Alpha
        CreateTenantResult orgAlpha;
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            orgAlpha = await tenantService.CreateTenantAsync(
                user.Id,
                new CreateTenantRequest($"wf3-alpha-{Guid.NewGuid():N}"[..24], "Alpha Logistics"));
            await tenantService.ActivateTenantAsync(orgAlpha.Response!.TenantId, adminActor);
        }

        // Create Organization Beta
        CreateTenantResult orgBeta;
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            orgBeta = await tenantService.CreateTenantAsync(
                user.Id,
                new CreateTenantRequest($"wf3-beta-{Guid.NewGuid():N}"[..24], "Beta Systems"));
            await tenantService.ActivateTenantAsync(orgBeta.Response!.TenantId, adminActor);
        }

        var tenantAId = orgAlpha.Response!.TenantId;
        var tenantBId = orgBeta.Response!.TenantId;

        // Act: 1. Neutral discovery query
        using (var context = CreateContext())
        {
            var membershipService = CreateMembershipService(context);
            var result = await membershipService.GetUserMembershipsAsync(user.Id, userActor);

            // Assert: Returned deterministic ordering (by DisplayName ascending)
            Assert.NotNull(result);
            Assert.Equal(2, result.Count);
            Assert.Equal("Alpha Logistics", result[0].TenantDisplayName);
            Assert.Equal("Beta Systems", result[1].TenantDisplayName);
        }

        // Assert: 2. Operational context selection isolates workspaces
        client.DefaultRequestHeaders.Remove("X-Tenant-ID");
        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenantAId.ToString());
        var respA = await client.GetAsync("/api/v1/tenancy/current");
        Assert.Equal(HttpStatusCode.OK, respA.StatusCode);
        var bodyA = await respA.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.Equal(tenantAId, bodyA!.TenantId);

        client.DefaultRequestHeaders.Remove("X-Tenant-ID");
        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenantBId.ToString());
        var respB = await client.GetAsync("/api/v1/tenancy/current");
        Assert.Equal(HttpStatusCode.OK, respB.StatusCode);
        var bodyB = await respB.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.Equal(tenantBId, bodyB!.TenantId);

        // Assert: 3. Cross-tenant isolation in TenantService queries
        var (foreignClient, foreignUser, _) = await CreateAuthenticatedUserAsync("wf3_foreign");
        var foreignActor = TenantActorContext.FromUser(foreignUser.Id);

        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);

            // In Alpha's context, querying Alpha tenant succeeds
            var alphaActor = TenantActorContext.Member(user.Id, tenantAId, TenantMembershipRole.Owner);
            var alphaTenant = await tenantService.GetTenantByIdAsync(tenantAId, alphaActor);
            Assert.True(alphaTenant.IsSuccess);
            Assert.Equal(200, alphaTenant.StatusCode);

            // Foreign user querying Alpha tenant is rejected with 404 (Anti-enumeration)
            var foreignTenantQuery = await tenantService.GetTenantByIdAsync(tenantAId, foreignActor);
            Assert.False(foreignTenantQuery.IsSuccess);
            Assert.Equal(404, foreignTenantQuery.StatusCode);
            Assert.Equal("TENANT_NOT_FOUND", foreignTenantQuery.ErrorCode);
        }
    }

    #endregion

    #region Workflow 4: Unauthorized Cross-Tenant Access

    [Fact]
    public async Task Workflow4_UnauthorizedCrossTenantAccess_DenialWithoutDataLeakage()
    {
        // Arrange
        var (victimClient, victimUser, _) = await CreateAuthenticatedUserAsync("wf4_victim");
        var (attackerClient, attackerUser, _) = await CreateAuthenticatedUserAsync("wf4_attacker");

        var victimActor = TenantActorContext.FromUser(victimUser.Id);
        var attackerActor = TenantActorContext.FromUser(attackerUser.Id);
        var adminActor = TenantActorContext.PlatformAdmin(Guid.NewGuid());

        CreateTenantResult victimTenant;
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            victimTenant = await tenantService.CreateTenantAsync(
                victimUser.Id,
                new CreateTenantRequest($"wf4-target-{Guid.NewGuid():N}"[..24], "Victim Enterprise"));
            await tenantService.ActivateTenantAsync(victimTenant.Response!.TenantId, adminActor);
        }

        var victimTenantId = victimTenant.Response!.TenantId;

        // Act & Assert 1: Attacker attempts resolution for victimTenant -> 404 Not Found (TD-09 anti-enumeration)
        attackerClient.DefaultRequestHeaders.Add("X-Tenant-ID", victimTenantId.ToString());
        var response = await attackerClient.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("The requested tenant organization was not found.", doc.RootElement.GetProperty("detail").GetString());

        // Act & Assert 2: Attacker attempts to query membership in victimTenant via TenantMembershipService -> AntiEnumeration (404 Not Found)
        using (var context = CreateContext())
        {
            var membershipService = CreateMembershipService(context);
            var memResult = await membershipService.GetMembershipAsync(victimTenantId, attackerUser.Id, attackerActor);

            Assert.False(memResult.IsSuccess);
            Assert.Equal(404, memResult.StatusCode);
            Assert.Equal("MEMBERSHIP_NOT_FOUND", memResult.ErrorCode);
        }

        // Act & Assert 3: Attacker attempts to read victim tenant metadata via TenantService -> AntiEnumeration (404 Not Found)
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            var tenantResult = await tenantService.GetTenantByIdAsync(victimTenantId, attackerActor);

            Assert.False(tenantResult.IsSuccess);
            Assert.Equal(404, tenantResult.StatusCode);
            Assert.Equal("TENANT_NOT_FOUND", tenantResult.ErrorCode);
        }
    }

    #endregion

    #region Workflow 5: Tenant Suspension

    [Fact]
    public async Task Workflow5_TenantSuspension_DurableAudit_ContextResolutionBlocked_OtherTenantsUnaffected()
    {
        // Arrange
        var (client, user, _) = await CreateAuthenticatedUserAsync("wf5_multi_owner");
        var adminUser = (await CreateAuthenticatedUserAsync("wf5_admin")).User;
        var adminActor = TenantActorContext.PlatformAdmin(adminUser.Id);

        CreateTenantResult tenantA;
        CreateTenantResult tenantB;
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            tenantA = await tenantService.CreateTenantAsync(
                user.Id,
                new CreateTenantRequest($"wf5-suspend-{Guid.NewGuid():N}"[..24], "Company To Suspend"));
            tenantB = await tenantService.CreateTenantAsync(
                user.Id,
                new CreateTenantRequest($"wf5-healthy-{Guid.NewGuid():N}"[..24], "Healthy Company"));

            await tenantService.ActivateTenantAsync(tenantA.Response!.TenantId, adminActor);
            await tenantService.ActivateTenantAsync(tenantB.Response!.TenantId, adminActor);
        }

        var tenantAId = tenantA.Response!.TenantId;
        var tenantBId = tenantB.Response!.TenantId;

        // Act: Suspend Tenant A with validated justification
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            var suspended = await tenantService.SuspendTenantAsync(
                tenantAId,
                "Billing delinquency and non-payment for 90 days.",
                adminActor);

            Assert.True(suspended.IsSuccess);
            Assert.Equal("Suspended", suspended.Response!.Status);
        }

        // Assert 1: Durable audit event for suspension
        using (var verifyContext = CreateContext())
        {
            var auditEvents = await verifyContext.TenantAuditEvents
                .AsNoTracking()
                .Where(a => a.TenantId == tenantAId && a.Action == "TenantSuspended")
                .ToListAsync();

            Assert.Single(auditEvents);
            var audit = auditEvents[0];
            Assert.Equal(adminUser.Id, audit.ActorUserId);
            Assert.Equal("Active", audit.PreviousStatus);
            Assert.Equal("Suspended", audit.NewStatus);
            Assert.Equal("Billing delinquency and non-payment for 90 days.", audit.Reason);
        }

        // Assert 2: Operational context resolution for Tenant A is BLOCKED (403 Forbidden)
        client.DefaultRequestHeaders.Remove("X-Tenant-ID");
        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenantAId.ToString());
        var respA = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.Forbidden, respA.StatusCode);
        var docA = JsonDocument.Parse(await respA.Content.ReadAsStringAsync());
        Assert.Equal("Access to the requested tenant organization is denied.", docA.RootElement.GetProperty("detail").GetString());

        // Assert 3: Tenant B remains completely unaffected and accessible (200 OK)
        client.DefaultRequestHeaders.Remove("X-Tenant-ID");
        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenantBId.ToString());
        var respB = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.OK, respB.StatusCode);
        var bodyB = await respB.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.NotNull(bodyB);
        Assert.Equal(tenantBId, bodyB.TenantId);
        Assert.Equal("Active", bodyB.Status);
    }

    #endregion

    #region Workflow 6: Audit Failure Rollback

    [Fact]
    public async Task Workflow6_AuditFailureRollback_TenantStatusAndVersionUnchanged()
    {
        // Arrange
        var owner = (await CreateAuthenticatedUserAsync("wf6_owner")).User;
        var adminUser = (await CreateAuthenticatedUserAsync("wf6_admin")).User;
        var adminActor = TenantActorContext.PlatformAdmin(adminUser.Id);

        CreateTenantResult initialTenant;
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            initialTenant = await tenantService.CreateTenantAsync(
                owner.Id,
                new CreateTenantRequest($"wf6-rollback-{Guid.NewGuid():N}"[..24], "Rollback Invariant Corp"));
        }

        var tenantId = initialTenant.Response!.TenantId;
        Assert.Equal("PendingOnboarding", initialTenant.Response.Status);

        long originalVersion;
        using (var checkContext = CreateContext())
        {
            var dbTenant = await checkContext.Tenants.AsNoTracking().SingleAsync(t => t.Id == tenantId);
            originalVersion = dbTenant.Version;
        }

        // Act: Attempt to activate tenant using a DbContext that injects a failure during audit save
        var failingInterceptor = new AuditFailureTestInterceptor();
        using (var failingContext = CreateContext(failingInterceptor))
        {
            var tenantService = CreateTenantService(failingContext);

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => tenantService.ActivateTenantAsync(tenantId, adminActor));
        }

        // Assert: Entire transaction rolled back cleanly
        using (var verifyContext = CreateContext())
        {
            var dbTenant = await verifyContext.Tenants.AsNoTracking().SingleOrDefaultAsync(t => t.Id == tenantId);
            Assert.NotNull(dbTenant);

            // 1. Status is still PendingOnboarding (NOT Active)
            Assert.Equal(TenantStatus.PendingOnboarding, dbTenant.Status);

            // 2. Version is unmutated
            Assert.Equal(originalVersion, dbTenant.Version);

            // 3. Zero audit event records were persisted
            var auditCount = await verifyContext.TenantAuditEvents
                .AsNoTracking()
                .CountAsync(a => a.TenantId == tenantId);

            Assert.Equal(0, auditCount);
        }
    }

    private sealed class AuditFailureTestInterceptor : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (eventData.Context is null)
            {
                return base.SavingChangesAsync(eventData, result, cancellationToken);
            }

            var hasAuditEvent = eventData.Context.ChangeTracker
                .Entries<TenantAuditEvent>()
                .Any(e => e.State == EntityState.Added);

            if (hasAuditEvent)
            {
                throw new InvalidOperationException("Simulated audit store connection disruption during transaction.");
            }

            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }

    #endregion

    #region Workflow 7: Revoked Membership & Re-Invitation

    [Fact]
    public async Task Workflow7_RevokedMembershipAndReinvitation_PreservesHistory_ResolvesCurrent()
    {
        // Arrange
        var (client, user, _) = await CreateAuthenticatedUserAsync("wf7_user");
        var userActor = TenantActorContext.FromUser(user.Id);
        var adminActor = TenantActorContext.PlatformAdmin(Guid.NewGuid());

        CreateTenantResult tenantResult;
        using (var context = CreateContext())
        {
            var tenantService = CreateTenantService(context);
            tenantResult = await tenantService.CreateTenantAsync(
                user.Id,
                new CreateTenantRequest($"wf7-history-{Guid.NewGuid():N}"[..24], "History Retention Corp"));
            await tenantService.ActivateTenantAsync(tenantResult.Response!.TenantId, adminActor);
        }

        var tenantId = tenantResult.Response!.TenantId;

        // Step 1: Revoke the membership
        DateTime revocationTime = DateTime.UtcNow;
        using (var context = CreateContext())
        {
            using (context.CreatePrivilegedTenantBypassScope("revoke-initial-membership"))
            {
                var membership = await context.TenantMemberships
                    .SingleAsync(m => m.TenantId == tenantId && m.UserId == user.Id);

                membership.Revoke(revocationTime);
                await context.SaveChangesAsync();
            }
        }

        // Assert 1: Operational context resolution is now denied (404 Not Found - TD-09 anti-enumeration)
        client.DefaultRequestHeaders.Add("X-Tenant-ID", tenantId.ToString());
        var revokedResp = await client.GetAsync("/api/v1/tenancy/current");

        Assert.Equal(HttpStatusCode.NotFound, revokedResp.StatusCode);
        var doc = JsonDocument.Parse(await revokedResp.Content.ReadAsStringAsync());
        Assert.Equal("The requested tenant organization was not found.", doc.RootElement.GetProperty("detail").GetString());

        // Assert 2: Neutral discovery hides revoked memberships
        using (var context = CreateContext())
        {
            var membershipService = CreateMembershipService(context);
            var discovery = await membershipService.GetUserMembershipsAsync(user.Id, userActor);

            Assert.NotNull(discovery);
            Assert.DoesNotContain(discovery, m => m.TenantId == tenantId);
        }

        // Step 2: User is re-invited and added as an Administrator
        DateTime reJoinTime = DateTime.UtcNow.AddMinutes(5);
        using (var context = CreateContext())
        {
            using (context.CreatePrivilegedTenantBypassScope("re-invite-user"))
            {
                var newMembership = TenantMembership.Create(
                    tenantId,
                    user.Id,
                    TenantMembershipRole.Administrator,
                    TenantMembershipStatus.Active,
                    reJoinTime);

                context.TenantMemberships.Add(newMembership);
                await context.SaveChangesAsync();
            }
        }

        // Assert 3: Both membership rows persist in the database (historical audit trail preserved)
        using (var verifyContext = CreateContext())
        {
            using (verifyContext.CreatePrivilegedTenantBypassScope("verify-historical-memberships"))
            {
                var allMemberships = await verifyContext.TenantMemberships
                    .AsNoTracking()
                    .Where(m => m.TenantId == tenantId && m.UserId == user.Id)
                    .OrderBy(m => m.CreatedAtUtc)
                    .ToListAsync();

                Assert.Equal(2, allMemberships.Count);

                // First membership remains Revoked
                Assert.Equal(TenantMembershipRole.Owner, allMemberships[0].Role);
                Assert.Equal(TenantMembershipStatus.Revoked, allMemberships[0].Status);
                Assert.NotNull(allMemberships[0].DeactivatedAtUtc);

                // Second membership is Active Administrator
                Assert.Equal(TenantMembershipRole.Administrator, allMemberships[1].Role);
                Assert.Equal(TenantMembershipStatus.Active, allMemberships[1].Status);
                Assert.Null(allMemberships[1].DeactivatedAtUtc);
            }
        }

        // Assert 4: Operational context resolution succeeds and picks the active Administrator membership
        var reJoinResp = await client.GetAsync("/api/v1/tenancy/current");
        Assert.Equal(HttpStatusCode.OK, reJoinResp.StatusCode);

        var currentContext = await reJoinResp.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.NotNull(currentContext);
        Assert.Equal(tenantId, currentContext.TenantId);
        Assert.Equal("Administrator", currentContext.Role);
        Assert.Equal("Active", currentContext.Status);

        // Assert 5: Neutral discovery now surfaces the active workspace with the updated role
        using (var context = CreateContext())
        {
            var membershipService = CreateMembershipService(context);
            var discovery = await membershipService.GetUserMembershipsAsync(user.Id, userActor);

            Assert.NotNull(discovery);
            var found = Assert.Single(discovery, m => m.TenantId == tenantId);
            Assert.Equal("Administrator", found.Role);
            Assert.Equal("Active", found.Status);
        }
    }

    #endregion
}
