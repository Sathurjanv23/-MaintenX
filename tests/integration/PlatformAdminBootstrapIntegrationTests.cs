namespace MaintenX.IntegrationTests;

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// PostgreSQL 16 integration tests for <see cref="PlatformAdminBootstrapService"/> and
/// <see cref="PlatformAdminBootstrapCommand"/> covering authorized first bootstrap,
/// idempotency, historical initialization protection, concurrent same-target and
/// different-target advisory-lock serialization, atomic grant+audit rollback,
/// and resolver/HTTP boundary preservation.
/// </summary>
public class PlatformAdminBootstrapIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public PlatformAdminBootstrapIntegrationTests()
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
    }

    public async Task DisposeAsync()
    {
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

    private static PlatformAdminBootstrapService CreateBootstrapService(
        MaintenXDbContext db,
        bool authorized = true)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [HostBootstrapOperatorAuthorizationProvider.AllowExecutionConfigKey] = authorized ? "true" : "false"
            })
            .Build();

        return new PlatformAdminBootstrapService(
            db,
            new HostBootstrapOperatorAuthorizationProvider(config),
            TimeProvider.System,
            NullLogger<PlatformAdminBootstrapService>.Instance);
    }

    [Fact]
    public async Task FreshMigratedDatabase_HasZeroSeededAdministratorGrants()
    {
        using var db = CreateDbContext();
        Assert.Equal(0, await db.PlatformRoleGrants.CountAsync());
    }

    [Fact]
    public async Task AuthorizedFirstBootstrap_RepeatedIdempotency_AndDifferentTargetRejection()
    {
        var now = DateTime.UtcNow;
        var userA = User.Create($"boot.a.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var userB = User.Create($"boot.b.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(userA, userB);
            await seedDb.SaveChangesAsync();
        }

        // A. First authorized bootstrap for User A
        PlatformAdminBootstrapResult r1;
        using (var db1 = CreateDbContext())
        {
            r1 = await CreateBootstrapService(db1)
                .BootstrapAsync(new PlatformAdminBootstrapRequest(userA.Id, null, "Initial production bootstrap"));
        }

        Assert.Equal(PlatformAdminBootstrapOutcome.Created, r1.Outcome);
        Assert.NotNull(r1.GrantId);
        Assert.NotNull(r1.AuditEventId);
        Assert.StartsWith("os:", r1.OperatorIdentity);

        using (var verifyDb = CreateDbContext())
        {
            var grant = await verifyDb.PlatformRoleGrants.AsNoTracking().SingleAsync(g => g.Id == r1.GrantId);
            Assert.Equal(GrantActorKind.DeploymentOperator, grant.GrantedByActorKind);
            Assert.Null(grant.GrantedByUserId);
            Assert.Equal(r1.OperatorIdentity, grant.GrantedByOperatorId);
            Assert.Equal(1, grant.Version);

            var audit = await verifyDb.SecurityAuditEvents.AsNoTracking().SingleAsync(a => a.Id == r1.AuditEventId);
            Assert.Equal(SecurityAuditEventType.PlatformAdministratorBootstrapped, audit.EventType);
            Assert.Equal(userA.Id, audit.UserId);
            Assert.NotNull(audit.Metadata);
            Assert.Equal(SecurityAuditMetadata.Reasons.PlatformAdministratorBootstrap, audit.Reason);
            Assert.Equal($"grant_{grant.Id:N}", audit.DetectedLineage);
            Assert.Equal(SecurityAuditMetadata.Actions.PlatformAdministratorGranted, audit.ActionTaken);
        }

        // B. Repeated same-target bootstrap -> idempotent, no duplicate grant or audit, Version stays 1
        using (var db2 = CreateDbContext())
        {
            var r2 = await CreateBootstrapService(db2)
                .BootstrapAsync(new PlatformAdminBootstrapRequest(null, userA.Email, "Repeated bootstrap"));
            Assert.Equal(PlatformAdminBootstrapOutcome.AlreadyProvisionedForSameUser, r2.Outcome);
            Assert.Equal(r1.GrantId, r2.GrantId);
            Assert.Null(r2.AuditEventId);
        }

        using (var verifyDb = CreateDbContext())
        {
            Assert.Equal(1, await verifyDb.PlatformRoleGrants.CountAsync());
            Assert.Equal(1, await verifyDb.SecurityAuditEvents.CountAsync(e => e.EventType == SecurityAuditEventType.PlatformAdministratorBootstrapped));
        }

        // C. Different-target bootstrap after initialization -> BootstrapUnavailable
        using (var db3 = CreateDbContext())
        {
            var r3 = await CreateBootstrapService(db3)
                .BootstrapAsync(new PlatformAdminBootstrapRequest(userB.Id, null, "Second user attempt"));
            Assert.Equal(PlatformAdminBootstrapOutcome.BootstrapUnavailable, r3.Outcome);
        }
    }

    [Fact]
    public async Task ConcurrentSameTargetBootstrap_CreatesExactlyOneGrantAndOneAudit()
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"concsame.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.Add(user);
            await seedDb.SaveChangesAsync();
        }

        using var db1 = CreateDbContext();
        using var db2 = CreateDbContext();

        var t1 = CreateBootstrapService(db1).BootstrapAsync(new PlatformAdminBootstrapRequest(user.Id, null, "Concurrent same 1"));
        var t2 = CreateBootstrapService(db2).BootstrapAsync(new PlatformAdminBootstrapRequest(user.Id, null, "Concurrent same 2"));
        var results = await Task.WhenAll(t1, t2);

        Assert.Equal(1, results.Count(r => r.Outcome == PlatformAdminBootstrapOutcome.Created));
        Assert.Equal(1, results.Count(r => r.Outcome == PlatformAdminBootstrapOutcome.AlreadyProvisionedForSameUser));

        using var verifyDb = CreateDbContext();
        Assert.Equal(1, await verifyDb.PlatformRoleGrants.CountAsync());
        Assert.Equal(1, await verifyDb.SecurityAuditEvents.CountAsync(e => e.EventType == SecurityAuditEventType.PlatformAdministratorBootstrapped));
    }

    [Fact]
    public async Task ConcurrentDifferentTargetBootstrap_ProvisionsExactlyOneUserAndRejectsOther()
    {
        var now = DateTime.UtcNow;
        var userA = User.Create($"concdiff.a.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var userB = User.Create($"concdiff.b.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(userA, userB);
            await seedDb.SaveChangesAsync();
        }

        using var db1 = CreateDbContext();
        using var db2 = CreateDbContext();

        var t1 = CreateBootstrapService(db1).BootstrapAsync(new PlatformAdminBootstrapRequest(userA.Id, null, "Concurrent A"));
        var t2 = CreateBootstrapService(db2).BootstrapAsync(new PlatformAdminBootstrapRequest(userB.Id, null, "Concurrent B"));
        var results = await Task.WhenAll(t1, t2);

        Assert.Equal(1, results.Count(r => r.Outcome == PlatformAdminBootstrapOutcome.Created));
        Assert.Equal(1, results.Count(r => r.Outcome == PlatformAdminBootstrapOutcome.BootstrapUnavailable));

        using var verifyDb = CreateDbContext();
        Assert.Equal(1, await verifyDb.PlatformRoleGrants.CountAsync());
        Assert.Equal(1, await verifyDb.SecurityAuditEvents.CountAsync(e => e.EventType == SecurityAuditEventType.PlatformAdministratorBootstrapped));
    }

    [Fact]
    public async Task MissingOrInactiveTarget_AndPreviouslyInitializedRevokedPlatform_AreRejectedWithZeroGrantsOrAudits()
    {
        var now = DateTime.UtcNow;
        var suspendedUser = User.Create($"susp.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        suspendedUser.Suspend(now);
        var activeUser = User.Create($"active.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(suspendedUser, activeUser);
            await seedDb.SaveChangesAsync();
        }

        using (var db = CreateDbContext())
        {
            Assert.Equal(PlatformAdminBootstrapOutcome.TargetNotFound,
                (await CreateBootstrapService(db).BootstrapAsync(new PlatformAdminBootstrapRequest(Guid.NewGuid(), null, "Missing user"))).Outcome);

            Assert.Equal(PlatformAdminBootstrapOutcome.TargetIneligible,
                (await CreateBootstrapService(db).BootstrapAsync(new PlatformAdminBootstrapRequest(suspendedUser.Id, null, "Suspended user"))).Outcome);
        }

        // Seed a historical revoked grant (previously initialized platform) -> first bootstrap must be rejected
        using (var histDb = CreateDbContext())
        {
            var hist = PlatformRoleGrant.CreateForBootstrap(activeUser.Id, PlatformRole.PlatformAdministrator, "os:init@host", now.AddHours(-2));
            hist.Revoke(activeUser.Id, "Historical revocation", now.AddHours(-1));
            histDb.PlatformRoleGrants.Add(hist);
            await histDb.SaveChangesAsync();
        }

        using (var dbAfterHist = CreateDbContext())
        {
            var res = await CreateBootstrapService(dbAfterHist)
                .BootstrapAsync(new PlatformAdminBootstrapRequest(activeUser.Id, null, "Attempt re-bootstrap after revocation"));
            Assert.Equal(PlatformAdminBootstrapOutcome.BootstrapUnavailable, res.Outcome);
        }

        // Active User-issued grant (e.g. from future standard grant flows) must not be treated as a completed bootstrap
        var normalAdmin = User.Create($"usergrant.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var granterUser = User.Create($"granter.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        using (var userGrantDb = CreateDbContext())
        {
            userGrantDb.Users.AddRange(normalAdmin, granterUser);
            var userGrant = PlatformRoleGrant.Create(normalAdmin.Id, PlatformRole.PlatformAdministrator, granterUser.Id, now);
            userGrantDb.PlatformRoleGrants.Add(userGrant);
            await userGrantDb.SaveChangesAsync();
        }

        using (var dbUserGrant = CreateDbContext())
        {
            var res = await CreateBootstrapService(dbUserGrant)
                .BootstrapAsync(new PlatformAdminBootstrapRequest(normalAdmin.Id, null, "Attempt bootstrap over user-issued grant"));
            Assert.Equal(PlatformAdminBootstrapOutcome.BootstrapUnavailable, res.Outcome);
        }

        using var verifyDb = CreateDbContext();
        Assert.Equal(0, await verifyDb.SecurityAuditEvents.CountAsync(e => e.EventType == SecurityAuditEventType.PlatformAdministratorBootstrapped));
    }

    [Fact]
    public async Task MigrationDowngrade_WithDeploymentOperatorGrant_FailsClosedTransactionally()
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"downgrade.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.Add(user);
            var bootstrapGrant = PlatformRoleGrant.CreateForBootstrap(
                user.Id,
                PlatformRole.PlatformAdministrator,
                "os:operator@deployment-node",
                now);
            var auditEvent = SecurityAuditEvent.Create(
                SecurityAuditEventType.PlatformAdministratorBootstrapped,
                now,
                userId: user.Id,
                sessionId: null,
                clientIp: null,
                metadata: SecurityAuditMetadata.ForBootstrap(bootstrapGrant.Id));

            seedDb.PlatformRoleGrants.Add(bootstrapGrant);
            seedDb.SecurityAuditEvents.Add(auditEvent);
            await seedDb.SaveChangesAsync();
        }

        // Attempting to downgrade past AddPlatformAdminBootstrapAttribution must fail because granted_by_user_id cannot be SET NOT NULL when NULL operator rows exist
        using (var downgradeDb = CreateDbContext())
        {
            var migrator = downgradeDb.GetInfrastructure().GetRequiredService<IMigrator>();
            await Assert.ThrowsAnyAsync<Exception>(() =>
                migrator.MigrateAsync("20261127110410_HardenPlatformRoleGrantConstraints"));
        }

        // Verify data remains fully intact and unchanged (atomic rollback on downgrade failure)
        using (var verifyDb = CreateDbContext())
        {
            var grant = await verifyDb.PlatformRoleGrants.AsNoTracking().SingleAsync(g => g.UserId == user.Id);
            Assert.Equal(GrantActorKind.DeploymentOperator, grant.GrantedByActorKind);
            Assert.Null(grant.GrantedByUserId);
            Assert.Equal("os:operator@deployment-node", grant.GrantedByOperatorId);

            var audit = await verifyDb.SecurityAuditEvents.AsNoTracking().SingleAsync(a => a.UserId == user.Id);
            Assert.Equal(SecurityAuditEventType.PlatformAdministratorBootstrapped, audit.EventType);
            Assert.Equal($"grant_{grant.Id:N}", audit.DetectedLineage);
        }
    }

    [Fact]
    public async Task AuditPersistenceFailure_RollsBackGrantAtomically()
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"rollback.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.Add(user);
            await seedDb.SaveChangesAsync();
        }

        // Drop check constraint or trigger failure on security_audit_events via a temporary trigger to force audit failure
        using (var setupDb = CreateDbContext())
        {
            await setupDb.Database.ExecuteSqlRawAsync(@"
                CREATE OR REPLACE FUNCTION platform.fail_bootstrap_audit_test() RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'Simulated audit persistence failure';
                END;
                $$ LANGUAGE plpgsql;
                CREATE TRIGGER trg_fail_bootstrap_audit
                BEFORE INSERT ON platform.security_audit_events
                FOR EACH ROW EXECUTE FUNCTION platform.fail_bootstrap_audit_test();");
        }

        try
        {
            using var db = CreateDbContext();
            var res = await CreateBootstrapService(db)
                .BootstrapAsync(new PlatformAdminBootstrapRequest(user.Id, null, "Trigger rollback"));

            Assert.Equal(PlatformAdminBootstrapOutcome.InfrastructureFailure, res.Outcome);

            using var verifyDb = CreateDbContext();
            Assert.Equal(0, await verifyDb.PlatformRoleGrants.CountAsync());
            Assert.Equal(0, await verifyDb.SecurityAuditEvents.CountAsync());
        }
        finally
        {
            using var cleanupDb = CreateDbContext();
            await cleanupDb.Database.ExecuteSqlRawAsync(@"
                DROP TRIGGER IF EXISTS trg_fail_bootstrap_audit ON platform.security_audit_events;
                DROP FUNCTION IF EXISTS platform.fail_bootstrap_audit_test();");
        }
    }

    [Fact]
    public async Task BootstrappedGrant_ResolvesViaRealJwtBearerPipeline_WhileHttpTenancyBoundaryRemainsUnchanged()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("ConnectionStrings:DefaultConnection", _isolatedConnectionString);
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:DefaultConnection"] = _isolatedConnectionString,
                    [HostBootstrapOperatorAuthorizationProvider.AllowExecutionConfigKey] = "true"
                });
            });
            builder.ConfigureServices(services =>
            {
                services.AddTransient<IStartupFilter, TestOnlyResolverEndpointFilter>();
            });
        });

        var client = factory.CreateClient();
        var email = $"boot_jwt_{Guid.NewGuid():N}@maintenx.dev";
        const string password = "SecurePassword123!";

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password))).StatusCode);
        var loginBody = await (await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password)))
            .Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        // Execute restricted CLI command in-process against factory services
        var exitCode = await PlatformAdminBootstrapCommand.ExecuteAsync(
            factory.Services,
            new[] { "--bootstrap-platform-admin", "--target-email", email, "--reason", "CLI bootstrap test" });
        Assert.Equal(0, exitCode);

        // Real JWT resolves platform permission through IPlatformGrantResolver
        using var req = new HttpRequestMessage(HttpMethod.Get, "/__test/platform-resolve?perm=platform.tenants.read");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", loginBody!.AccessToken);
        using var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // Existing HTTP tenant lifecycle route remains unexposed / blocked
        using var lifecycleReq = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenants/{Guid.NewGuid()}/activate");
        lifecycleReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", loginBody.AccessToken);
        using var lifecycleResp = await client.SendAsync(lifecycleReq);
        Assert.True(lifecycleResp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Forbidden or HttpStatusCode.MethodNotAllowed);
    }

    private sealed class TestOnlyResolverEndpointFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                next(app);
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/__test/platform-resolve", async (
                        IPlatformGrantResolver resolver,
                        HttpContext ctx,
                        CancellationToken ct) =>
                    {
                        var permStr = ctx.Request.Query["perm"].ToString();
                        PermissionKey? perm = PermissionKey.TryParse(permStr, out var parsed) ? parsed : null;
                        var result = await resolver.ResolveAsync(perm, ct);
                        return result.IsAllowed
                            ? Results.Ok(new { result.IsAllowed })
                            : Results.Json(new { result.IsAllowed, result.DenialReason }, statusCode: StatusCodes.Status403Forbidden);
                    });
                });
            };
        }
    }
}
