namespace MaintenX.IntegrationTests;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

/// <summary>
/// FEAT-004 Task 4.2.3 RBAC persistence security verification tests.
/// Verifies global scope isolation across tenant contexts, premature authority protection,
/// HTTP exposure boundaries, transactional optimistic concurrency, corrective migration safety
/// with existing valid grants, and full authentication/audit data preservation.
/// </summary>
public class PlatformRoleGrantPersistenceSecurityTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public PlatformRoleGrantPersistenceSecurityTests()
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

    private MaintenXDbContext CreateDbContext(ITenantContextAccessor? tenantContextAccessor = null)
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return tenantContextAccessor is null
            ? new MaintenXDbContext(options)
            : new MaintenXDbContext(options, tenantContextAccessor);
    }

    private HttpClient CreateUniqueClient()
    {
        return _factory.CreateClient();
    }

    // =========================================================================
    // 1. Global Scope Isolation Across Tenant Contexts
    // =========================================================================

    [Fact]
    public async Task GlobalScope_PlatformRoleGrants_UnfilteredAcrossNoTenantTenantAAndTenantB_WhileTenantEntitiesRemainIsolated()
    {
        var now = DateTime.UtcNow;
        var tenantA = Tenant.Create("scope-tenant-a", "Scope Tenant A", TenantStatus.Active);
        var tenantB = Tenant.Create("scope-tenant-b", "Scope Tenant B", TenantStatus.Active);
        var userA = User.Create($"scope.a.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var userB = User.Create($"scope.b.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var membershipA = TenantMembership.Create(tenantA.Id, userA.Id, TenantMembershipRole.Owner);
        var membershipB = TenantMembership.Create(tenantB.Id, userB.Id, TenantMembershipRole.Owner);

        using (var seedDb = CreateDbContext())
        {
            seedDb.CreatePrivilegedTenantBypassScope("seed-scope-test");
            seedDb.Tenants.AddRange(tenantA, tenantB);
            seedDb.Users.AddRange(userA, userB);
            seedDb.TenantMemberships.AddRange(membershipA, membershipB);
            await seedDb.SaveChangesAsync();
        }

        // A. No active tenant context & no privileged bypass: PlatformRoleGrant writes & reads succeed globally
        var globalGrant = PlatformRoleGrant.Create(userA.Id, PlatformRole.PlatformAdministrator, userB.Id, now);
        using (var noTenantDb = CreateDbContext(new TenantContextAccessor()))
        {
            noTenantDb.PlatformRoleGrants.Add(globalGrant);
            await noTenantDb.SaveChangesAsync();

            Assert.Single(await noTenantDb.PlatformRoleGrants.Where(g => g.Id == globalGrant.Id).ToListAsync());
            // Without tenant context or bypass, tenant-owned entities remain fail-closed (0 rows)
            Assert.Empty(await noTenantDb.TenantMemberships.ToListAsync());
        }

        // B & C & D. Parallel Tenant A and Tenant B contexts see global grants while isolating tenant memberships
        var accessorA = new TenantContextAccessor();
        accessorA.SetContext(new TenantContext(
            tenantA.Id, tenantA.Slug, tenantA.DisplayName, userA.Id, membershipA.Id,
            TenantMembershipRole.Owner, TenantMembershipStatus.Active, now));

        var accessorB = new TenantContextAccessor();
        accessorB.SetContext(new TenantContext(
            tenantB.Id, tenantB.Slug, tenantB.DisplayName, userB.Id, membershipB.Id,
            TenantMembershipRole.Owner, TenantMembershipStatus.Active, now));

        using var dbA = CreateDbContext(accessorA);
        using var dbB = CreateDbContext(accessorB);

        var taskA = Task.Run(async () =>
        {
            var grants = await dbA.PlatformRoleGrants.AsNoTracking().Where(g => g.Id == globalGrant.Id).ToListAsync();
            var memberships = await dbA.TenantMemberships.AsNoTracking().ToListAsync();
            return (grants, memberships);
        });

        var taskB = Task.Run(async () =>
        {
            var grants = await dbB.PlatformRoleGrants.AsNoTracking().Where(g => g.Id == globalGrant.Id).ToListAsync();
            var memberships = await dbB.TenantMemberships.AsNoTracking().ToListAsync();
            return (grants, memberships);
        });

        var results = await Task.WhenAll(taskA, taskB);

        Assert.Single(results[0].grants);
        Assert.Single(results[0].memberships);
        Assert.Equal(tenantA.Id, results[0].memberships[0].TenantId);

        Assert.Single(results[1].grants);
        Assert.Single(results[1].memberships);
        Assert.Equal(tenantB.Id, results[1].memberships[0].TenantId);
    }

    // =========================================================================
    // 2. Premature Authority Activation & HTTP Exposure Protection
    // =========================================================================

    [Fact]
    public async Task PrematureAuthorityProtection_ActivePlatformRoleGrant_DoesNotElevateHttpActorOrExposeGrants()
    {
        var client = CreateUniqueClient();
        var email = $"premature_admin_{Guid.NewGuid():N}@maintenx.dev";
        const string password = "SecurePassword123!";

        var regResp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, regResp.StatusCode);

        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginBody!.AccessToken);

        Guid userId;
        Guid tenantId;
        using (var db = CreateDbContext())
        {
            var user = await db.Users.SingleAsync(u => u.Email == email);
            userId = user.Id;

            var grant = PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, user.Id, DateTime.UtcNow);
            db.PlatformRoleGrants.Add(grant);
            await db.SaveChangesAsync();
        }

        // Create a tenant as ordinary authenticated user
        var createTenantResp = await client.PostAsJsonAsync("/api/v1/tenants", new { slug = $"org-{Guid.NewGuid():N}"[..16], displayName = "Test Org" });
        Assert.Equal(HttpStatusCode.Created, createTenantResp.StatusCode);
        var tenantJson = await createTenantResp.Content.ReadAsStringAsync();
        using (var doc = JsonDocument.Parse(tenantJson))
        {
            tenantId = doc.RootElement.GetProperty("tenantId").GetGuid();
        }

        // Ordinary tenancy endpoints must NOT serialize or expose PlatformRoleGrant data
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenantId.ToString());
        var getTenantResp = await client.GetAsync($"/api/v1/tenants/{tenantId}");
        Assert.Equal(HttpStatusCode.OK, getTenantResp.StatusCode);
        var getTenantBody = await getTenantResp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("platformRoleGrant", getTenantBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PlatformAdministrator", getTenantBody, StringComparison.OrdinalIgnoreCase);

        var meResp = await client.GetAsync("/api/v1/tenants/me");
        Assert.Equal(HttpStatusCode.OK, meResp.StatusCode);
        var meBody = await meResp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("platformRoleGrant", meBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PlatformAdministrator", meBody, StringComparison.OrdinalIgnoreCase);

        // Even with a persisted Active PlatformRoleGrant + forged header, platform lifecycle routes remain blocked (403/404/405)
        client.DefaultRequestHeaders.Add("X-Platform-Admin", "true");
        var activateResp = await client.PostAsync($"/api/v1/tenants/{tenantId}/activate", null);
        Assert.True(
            activateResp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed,
            $"Expected blocked platform lifecycle route, got {activateResp.StatusCode}");

        // No platform grant CRUD endpoint exists
        var grantsRouteResp = await client.GetAsync("/api/v1/platform/role-grants");
        Assert.Equal(HttpStatusCode.NotFound, grantsRouteResp.StatusCode);
    }

    // =========================================================================
    // 3. Transactional Optimistic Concurrency Regression
    // =========================================================================

    [Fact]
    public async Task OptimisticConcurrency_StaleTransactionUpdate_LeavesOriginalRevocationIntactWithoutDuplicateHistory()
    {
        var now = DateTime.UtcNow;
        var target = User.Create($"conc.target.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var actorA = User.Create($"conc.actora.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var actorB = User.Create($"conc.actorb.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var grant = PlatformRoleGrant.Create(target.Id, PlatformRole.PlatformAdministrator, actorA.Id, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(target, actorA, actorB);
            seedDb.PlatformRoleGrants.Add(grant);
            await seedDb.SaveChangesAsync();
        }

        using var db1 = CreateDbContext();
        using var db2 = CreateDbContext();

        var copy1 = await db1.PlatformRoleGrants.SingleAsync(g => g.Id == grant.Id);
        var copy2 = await db2.PlatformRoleGrants.SingleAsync(g => g.Id == grant.Id);

        var revokeTime1 = now.AddMinutes(5);
        await using (var tx1 = await db1.Database.BeginTransactionAsync())
        {
            copy1.Revoke(actorA.Id, "Authoritative revocation by Actor A", revokeTime1);
            await db1.SaveChangesAsync();
            await tx1.CommitAsync();
        }

        await using (var tx2 = await db2.Database.BeginTransactionAsync())
        {
            copy2.Revoke(actorB.Id, "Stale revocation by Actor B", now.AddMinutes(6));
            await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => db2.SaveChangesAsync());
            await tx2.RollbackAsync();
        }

        using var verifyDb = CreateDbContext();
        var persisted = await verifyDb.PlatformRoleGrants.AsNoTracking().Where(g => g.UserId == target.Id).ToListAsync();
        var single = Assert.Single(persisted);
        Assert.Equal(grant.Id, single.Id);
        Assert.Equal(PlatformRoleGrantStatus.Revoked, single.Status);
        Assert.Equal(2, single.Version);
        Assert.Equal(actorA.Id, single.RevokedByUserId);
        Assert.Equal("Authoritative revocation by Actor A", single.RevocationReason);
    }

    // =========================================================================
    // 4. Corrective Migration Safety & Rollback With Existing Valid Grants
    // =========================================================================

    [Fact]
    public async Task CorrectiveMigration_PreservesValidExistingGrants_AndRollbackPreservesValidRecords()
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

                using var ctx = new MaintenXDbContext(options);
                var migrator = ctx.GetInfrastructure().GetRequiredService<IMigrator>();
                await migrator.MigrateAsync("20261127103956_AddPlatformRoleGrantPersistence");
            });

        try
        {
            var options = new DbContextOptionsBuilder<MaintenXDbContext>()
                .UseNpgsql(connStr)
                .Options;

            var now = new DateTime(2026, 11, 27, 11, 0, 0, DateTimeKind.Utc);
            Guid activeId;
            Guid revokedId;

            using (var seedCtx = new MaintenXDbContext(options))
            {
                var u1 = User.Create("corr.u1@maintenx.internal", "hash", UserStatus.Active, now);
                var u2 = User.Create("corr.u2@maintenx.internal", "hash", UserStatus.Active, now);
                seedCtx.Users.AddRange(u1, u2);

                var activeGrant = PlatformRoleGrant.Create(u1.Id, PlatformRole.PlatformAdministrator, u2.Id, now);
                var revokedGrant = PlatformRoleGrant.Create(u2.Id, PlatformRole.PlatformAdministrator, u1.Id, now);
                revokedGrant.Revoke(u1.Id, "Valid historical revocation", now.AddMinutes(1));
                seedCtx.PlatformRoleGrants.AddRange(activeGrant, revokedGrant);

                await seedCtx.SaveChangesAsync();
                activeId = activeGrant.Id;
                revokedId = revokedGrant.Id;
            }

            using (var upgradeCtx = new MaintenXDbContext(options))
            {
                await upgradeCtx.Database.MigrateAsync();
                Assert.False(upgradeCtx.Database.HasPendingModelChanges());

                Assert.NotNull(await upgradeCtx.PlatformRoleGrants.AsNoTracking().SingleOrDefaultAsync(g => g.Id == activeId));
                Assert.NotNull(await upgradeCtx.PlatformRoleGrants.AsNoTracking().SingleOrDefaultAsync(g => g.Id == revokedId));

                // Roll back only HardenPlatformRoleGrantConstraints -> valid records remain intact
                var migrator = upgradeCtx.GetInfrastructure().GetRequiredService<IMigrator>();
                await migrator.MigrateAsync("20261127103956_AddPlatformRoleGrantPersistence");

                Assert.Equal(2, await upgradeCtx.PlatformRoleGrants.AsNoTracking().CountAsync());

                // Re-apply latest migration cleanly
                await upgradeCtx.Database.MigrateAsync();
                Assert.Equal(2, await upgradeCtx.PlatformRoleGrants.AsNoTracking().CountAsync());
            }
        }
        finally
        {
            await TestDatabaseGuard.DropDatabaseSafelyAsync(dbName, _adminConnectionString);
        }
    }

    // =========================================================================
    // 5. Full Auth & Audit Preservation Across Both Platform Grant Migrations
    // =========================================================================

    [Fact]
    public async Task MigrationUpgrade_PreservesAuthenticationAndAuditRecords_WithZeroSeededAdmins()
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

                using var ctx = new MaintenXDbContext(options);
                var migrator = ctx.GetInfrastructure().GetRequiredService<IMigrator>();
                await migrator.MigrateAsync("20261124000000_AddTenantAuditPersistence");
            });

        try
        {
            var options = new DbContextOptionsBuilder<MaintenXDbContext>()
                .UseNpgsql(connStr)
                .Options;

            var now = new DateTime(2026, 11, 27, 10, 0, 0, DateTimeKind.Utc);
            Guid sessionId;
            Guid tokenId;
            Guid securityAuditId;
            Guid tenantAuditId;

            using (var seedCtx = new MaintenXDbContext(options))
            {
                seedCtx.CreatePrivilegedTenantBypassScope("auth-audit-preserve");
                var tenant = Tenant.Create("auth-audit-org", "Auth Audit Org", TenantStatus.Active);
                var user = User.Create("preserve.auth@maintenx.internal", "hash_value", UserStatus.Active, now);
                var session = UserSession.Create(user.Id, now, TimeSpan.FromDays(7));
                var syntheticHash = new string('a', 64);
                var token = RefreshToken.Create(session, syntheticHash, now, TimeSpan.FromDays(7));
                var secAudit = SecurityAuditEvent.Create(
                    SecurityAuditEventType.LoginSuccess, now, user.Id, session.Id, "203.0.113.10");
                var tenantAudit = TenantAuditEvent.Create(
                    tenant.Id, user.Id, "TenantSettingsUpdated", "Active", "Active", "Pre-migration settings change", now);

                seedCtx.Tenants.Add(tenant);
                seedCtx.Users.Add(user);
                seedCtx.UserSessions.Add(session);
                seedCtx.RefreshTokens.Add(token);
                seedCtx.SecurityAuditEvents.Add(secAudit);
                seedCtx.TenantAuditEvents.Add(tenantAudit);
                await seedCtx.SaveChangesAsync();

                sessionId = session.Id;
                tokenId = token.Id;
                securityAuditId = secAudit.Id;
                tenantAuditId = tenantAudit.Id;
            }

            using (var verifyCtx = new MaintenXDbContext(options))
            {
                await verifyCtx.Database.MigrateAsync();
                Assert.False(verifyCtx.Database.HasPendingModelChanges());

                verifyCtx.CreatePrivilegedTenantBypassScope("auth-audit-verify");
                var loadedSession = await verifyCtx.UserSessions.AsNoTracking().SingleAsync(s => s.Id == sessionId);
                var loadedToken = await verifyCtx.RefreshTokens.AsNoTracking().SingleAsync(t => t.Id == tokenId);
                var loadedSecAudit = await verifyCtx.SecurityAuditEvents.AsNoTracking().SingleAsync(e => e.Id == securityAuditId);
                var loadedTenantAudit = await verifyCtx.TenantAuditEvents.AsNoTracking().SingleAsync(e => e.Id == tenantAuditId);

                Assert.Equal(new string('a', 64), loadedToken.TokenHash);
                Assert.Equal(loadedSession.Id, loadedToken.SessionId);
                Assert.Equal(SecurityAuditEventType.LoginSuccess, loadedSecAudit.EventType);
                Assert.Equal("TenantSettingsUpdated", loadedTenantAudit.Action);
                Assert.Equal(0, await verifyCtx.PlatformRoleGrants.CountAsync());
            }
        }
        finally
        {
            await TestDatabaseGuard.DropDatabaseSafelyAsync(dbName, _adminConnectionString);
        }
    }
}
