namespace MaintenX.IntegrationTests;

using System.Data;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// PostgreSQL 16 integration tests for <see cref="PlatformGrantService"/> covering:
/// 1. Authorized administrator grant revocation and durable session_revoked audit trail.
/// 2. Protection of the last distinct active eligible platform administrator.
/// 3. Self-revocation conservative denial.
/// 4. ExpectedVersion concurrency conflict handling.
/// 5. Revocation of grant immediately causes subsequent Bearer resolution to fail for the same JWT.
/// 6. Concurrent cross-revocation advisory lock serialization (two admins revoking each other).
/// 7. Repeated revocation idempotency.
/// </summary>
public class PlatformGrantRevocationIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public PlatformGrantRevocationIntegrationTests()
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

    [Fact]
    public async Task RevokeGrantAsync_LastPlatformAdmin_IsProtectedAndDenied()
    {
        var now = DateTime.UtcNow;
        var adminUser = User.Create($"lastadmin.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var callerUser = User.Create($"caller.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Suspended, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(adminUser, callerUser);
            var grant1 = PlatformRoleGrant.CreateForBootstrap(adminUser.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", now);
            var callerGrant = PlatformRoleGrant.Create(callerUser.Id, PlatformRole.PlatformAdministrator, adminUser.Id, now);
            seedDb.PlatformRoleGrants.AddRange(grant1, callerGrant);
            await seedDb.SaveChangesAsync();
        }

        // Caller is callerUser (whose account is suspended, so remaining eligible admin count excluding adminUser is 0)
        using var db = CreateDbContext();
        var stubResolver = new FixedUserGrantResolver(callerUser.Id);
        var grantService = new PlatformGrantService(db, stubResolver, TimeProvider.System, NullLogger<PlatformGrantService>.Instance);

        var grantToRevoke = await db.PlatformRoleGrants.SingleAsync(g => g.UserId == adminUser.Id);
        var result = await grantService.RevokeGrantAsync(new PlatformGrantRevocationRequest(grantToRevoke.Id, "Attempt revoke only admin"));

        Assert.Equal(PlatformGrantRevocationOutcome.LastAdministratorProtected, result.Outcome);
        Assert.False(result.IsSuccess);

        // Verify grant remains Active
        var refreshedGrant = await db.PlatformRoleGrants.AsNoTracking().SingleAsync(g => g.Id == grantToRevoke.Id);
        Assert.Equal(PlatformRoleGrantStatus.Active, refreshedGrant.Status);
    }

    [Fact]
    public async Task RevokeGrantAsync_SelfRevocation_IsDenied()
    {
        var now = DateTime.UtcNow;
        var admin1 = User.Create($"self1.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var admin2 = User.Create($"self2.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(admin1, admin2);
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(admin1.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", now));
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(admin2.Id, PlatformRole.PlatformAdministrator, admin1.Id, now));
            await seedDb.SaveChangesAsync();
        }

        using var db = CreateDbContext();
        var admin1Grant = await db.PlatformRoleGrants.SingleAsync(g => g.UserId == admin1.Id);

        // Caller is admin1 trying to revoke admin1's own grant
        var stubResolver = new FixedUserGrantResolver(admin1.Id);
        var grantService = new PlatformGrantService(db, stubResolver, TimeProvider.System, NullLogger<PlatformGrantService>.Instance);

        var result = await grantService.RevokeGrantAsync(new PlatformGrantRevocationRequest(admin1Grant.Id, "Self revocation attempt"));
        Assert.Equal(PlatformGrantRevocationOutcome.SelfRevocationDenied, result.Outcome);
        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task RevokeGrantAsync_TwoAdmins_OneRevokesOther_SucceedsWithCorrelatedAudit()
    {
        var now = DateTime.UtcNow;
        var admin1 = User.Create($"adm1.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var admin2 = User.Create($"adm2.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(admin1, admin2);
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(admin1.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", now));
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(admin2.Id, PlatformRole.PlatformAdministrator, admin1.Id, now));
            await seedDb.SaveChangesAsync();
        }

        using var db = CreateDbContext();
        var admin2Grant = await db.PlatformRoleGrants.SingleAsync(g => g.UserId == admin2.Id);

        // Caller is admin1 revoking admin2
        var stubResolver = new FixedUserGrantResolver(admin1.Id);
        var grantService = new PlatformGrantService(db, stubResolver, TimeProvider.System, NullLogger<PlatformGrantService>.Instance);

        var result = await grantService.RevokeGrantAsync(new PlatformGrantRevocationRequest(admin2Grant.Id, "Security rotation"));
        Assert.Equal(PlatformGrantRevocationOutcome.Revoked, result.Outcome);
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.AuditEventId);

        // Verify DB state
        using var verifyDb = CreateDbContext();
        var revokedGrant = await verifyDb.PlatformRoleGrants.SingleAsync(g => g.Id == admin2Grant.Id);
        Assert.Equal(PlatformRoleGrantStatus.Revoked, revokedGrant.Status);
        Assert.Equal(admin1.Id, revokedGrant.RevokedByUserId);
        Assert.Equal("Security rotation", revokedGrant.RevocationReason);
        Assert.Equal(2, revokedGrant.Version);

        var audit = await verifyDb.SecurityAuditEvents.SingleAsync(a => a.Id == result.AuditEventId);
        Assert.Equal(SecurityAuditEventType.SessionRevoked, audit.EventType);
        Assert.Equal(admin2.Id, audit.UserId);
        Assert.Equal($"grant_{admin2Grant.Id:N}", audit.DetectedLineage);

        // Repeated revocation is idempotent no-op
        var repeatResult = await grantService.RevokeGrantAsync(new PlatformGrantRevocationRequest(admin2Grant.Id, "Repeated revocation"));
        Assert.Equal(PlatformGrantRevocationOutcome.AlreadyRevoked, repeatResult.Outcome);
        Assert.True(repeatResult.IsSuccess);
    }

    [Fact]
    public async Task RevokeGrantAsync_ExpectedVersionMismatch_ReturnsConcurrencyConflict()
    {
        var now = DateTime.UtcNow;
        var admin1 = User.Create($"ver1.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var admin2 = User.Create($"ver2.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(admin1, admin2);
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(admin1.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", now));
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(admin2.Id, PlatformRole.PlatformAdministrator, admin1.Id, now));
            await seedDb.SaveChangesAsync();
        }

        using var db = CreateDbContext();
        var admin2Grant = await db.PlatformRoleGrants.SingleAsync(g => g.UserId == admin2.Id);

        var stubResolver = new FixedUserGrantResolver(admin1.Id);
        var grantService = new PlatformGrantService(db, stubResolver, TimeProvider.System, NullLogger<PlatformGrantService>.Instance);

        var result = await grantService.RevokeGrantAsync(new PlatformGrantRevocationRequest(
            admin2Grant.Id,
            "Version mismatch test",
            ExpectedVersion: 99));

        Assert.Equal(PlatformGrantRevocationOutcome.ConcurrencyConflict, result.Outcome);
        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task ConcurrentCrossRevocation_TwoAdminsRevokingEachOther_SerializesAndProtectsLastAdmin()
    {
        var now = DateTime.UtcNow;
        var adminA = User.Create($"cross.a.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var adminB = User.Create($"cross.b.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(adminA, adminB);
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(adminA.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", now));
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(adminB.Id, PlatformRole.PlatformAdministrator, adminA.Id, now));
            await seedDb.SaveChangesAsync();
        }

        using var dbA = CreateDbContext();
        using var dbB = CreateDbContext();

        var grantA = await dbA.PlatformRoleGrants.SingleAsync(g => g.UserId == adminA.Id);
        var grantB = await dbA.PlatformRoleGrants.SingleAsync(g => g.UserId == adminB.Id);

        var serviceA = new PlatformGrantService(dbA, new FixedUserGrantResolver(adminA.Id), TimeProvider.System, NullLogger<PlatformGrantService>.Instance);
        var serviceB = new PlatformGrantService(dbB, new FixedUserGrantResolver(adminB.Id), TimeProvider.System, NullLogger<PlatformGrantService>.Instance);

        // A tries to revoke B while B tries to revoke A simultaneously
        var taskA = serviceA.RevokeGrantAsync(new PlatformGrantRevocationRequest(grantB.Id, "A revokes B"));
        var taskB = serviceB.RevokeGrantAsync(new PlatformGrantRevocationRequest(grantA.Id, "B revokes A"));

        var results = await Task.WhenAll(taskA, taskB);

        // Exactly one revocation must succeed, and the second must be denied (either LastAdminProtected or Unauthorized because caller was already revoked)
        var successes = results.Count(r => r.Outcome == PlatformGrantRevocationOutcome.Revoked);
        Assert.Equal(1, successes);

        var failures = results.Count(r => r.Outcome is PlatformGrantRevocationOutcome.LastAdministratorProtected or PlatformGrantRevocationOutcome.Unauthorized);
        Assert.Equal(1, failures);

        // Verify exactly one active admin grant survives
        using var verifyDb = CreateDbContext();
        Assert.Equal(1, await verifyDb.PlatformRoleGrants.CountAsync(g => g.Status == PlatformRoleGrantStatus.Active));
    }

    [Fact]
    public async Task RevokedGrant_ImmediatelyDeniesSubsequentBearerResolution_UsingSameJwt()
    {
        var password = "ValidPassword123!";
        var email1 = $"liveadm1.{Guid.NewGuid():N}@maintenx.internal";
        var email2 = $"liveadm2.{Guid.NewGuid():N}@maintenx.internal";

        using var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
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
                        ["TrustedProxies:ForwardLimit"] = "1",
                        ["MaintenX:Bootstrap:AllowExecution"] = "true"
                    });
                });
                builder.ConfigureServices(services =>
                {
                    services.AddSingleton<IStartupFilter, TestSocketSimulationAndResolverFilter>();
                });
            });

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", "127.0.0.1");

        // 1. Register and login admin2
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email2, password))).StatusCode);

        var login2Resp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email2, password));
        Assert.Equal(HttpStatusCode.OK, login2Resp.StatusCode);
        var login2 = await login2Resp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(login2);

        // 2. Create and bootstrap admin1 directly in DB
        Guid admin1UserId;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();
            var user1 = User.Create(email1, "hash", UserStatus.Active, DateTime.UtcNow);
            db.Users.Add(user1);
            await db.SaveChangesAsync();
            admin1UserId = user1.Id;

            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(user1.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", DateTime.UtcNow));
            await db.SaveChangesAsync();
        }

        // 3. Admin1 grants Admin2 platform administrator grant
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();
            var user2 = await db.Users.SingleAsync(u => u.Email == email2);
            db.PlatformRoleGrants.Add(PlatformRoleGrant.Create(user2.Id, PlatformRole.PlatformAdministrator, admin1UserId, DateTime.UtcNow));
            await db.SaveChangesAsync();
        }

        // 4. Admin2 resolves successfully before revocation
        using (var req = new HttpRequestMessage(HttpMethod.Get, "/__test/platform-resolve?perm=platform.tenants.read"))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", login2.AccessToken);
            using var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }

        // 5. Admin1 revokes Admin2's grant using IPlatformGrantService
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();
            var user2 = await db.Users.SingleAsync(u => u.Email == email2);
            var grant2 = await db.PlatformRoleGrants.SingleAsync(g => g.UserId == user2.Id && g.Status == PlatformRoleGrantStatus.Active);

            var grantService = new PlatformGrantService(
                db,
                new FixedUserGrantResolver(admin1UserId),
                TimeProvider.System,
                NullLogger<PlatformGrantService>.Instance);

            var revokeResult = await grantService.RevokeGrantAsync(new PlatformGrantRevocationRequest(grant2.Id, "Revocation for live token test"));
            Assert.Equal(PlatformGrantRevocationOutcome.Revoked, revokeResult.Outcome);
        }

        // 6. Admin2 attempts same operation with existing valid JWT -> must be Forbidden (403)
        using (var req = new HttpRequestMessage(HttpMethod.Get, "/__test/platform-resolve?perm=platform.tenants.read"))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", login2.AccessToken);
            using var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }
    }

    private sealed class FixedUserGrantResolver(Guid userId) : IPlatformGrantResolver
    {
        public Task<PlatformGrantResolutionResult> ResolveAsync(PermissionKey? permission, CancellationToken cancellationToken = default) =>
            Task.FromResult(PlatformGrantResolutionResult.Allow(
                userId,
                Guid.NewGuid(),
                PlatformRole.PlatformAdministrator,
                permission ?? PermissionCatalog.Platform.TenantsRead));
    }

    private sealed class TestSocketSimulationAndResolverFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                app.Use(async (context, nextMiddleware) =>
                {
                    if (context.Request.Headers.TryGetValue("X-Test-Socket-Remote-Ip", out var socketIpHeader) &&
                        System.Net.IPAddress.TryParse(socketIpHeader.ToString(), out var socketIp))
                    {
                        context.Connection.RemoteIpAddress = socketIp;
                    }
                    else
                    {
                        context.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
                    }

                    await nextMiddleware();
                });

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
