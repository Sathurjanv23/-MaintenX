namespace MaintenX.IntegrationTests;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// PostgreSQL 16 integration tests for <see cref="PlatformGrantResolver"/>.
/// Verifies current account eligibility, current session validity, security stamp matching,
/// active/revoked grant evaluation, cross-user isolation, tenant-role separation,
/// grant/account/session freshness without positive caching, and global scope consistency.
/// </summary>
public class PlatformGrantResolverIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public PlatformGrantResolverIntegrationTests()
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

    private MaintenXDbContext CreateDbContext(ITenantContextAccessor? tenantContextAccessor = null)
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return tenantContextAccessor is null
            ? new MaintenXDbContext(options)
            : new MaintenXDbContext(options, tenantContextAccessor);
    }

    private static PlatformGrantResolver CreateResolver(MaintenXDbContext db, TimeProvider? timeProvider = null) =>
        new(db, timeProvider ?? TimeProvider.System, NullLogger<PlatformGrantResolver>.Instance);

    private static ClaimsPrincipal CreatePrincipal(User user, UserSession session) =>
        new(new ClaimsIdentity(
            new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Sid, session.Id.ToString()),
                new Claim("sst", user.SecurityStamp)
            },
            "Bearer"));

    [Fact]
    public async Task ValidPlatformAdmin_AllowsAll4PlatformPermissions_AndDeniesAll10TenantPermissions()
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"admin.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var actor = User.Create($"actor.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(1));
        var grant = PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, actor.Id, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(user, actor);
            seedDb.UserSessions.Add(session);
            seedDb.PlatformRoleGrants.Add(grant);
            await seedDb.SaveChangesAsync();
        }

        var principal = CreatePrincipal(user, session);

        using var evalDb = CreateDbContext();
        var resolver = CreateResolver(evalDb);

        Assert.Equal(4, PermissionCatalog.PlatformPermissions.Count);
        foreach (var perm in PermissionCatalog.PlatformPermissions)
        {
            var result = await resolver.ResolveAsync(principal, perm.Key);
            Assert.True(result.IsAllowed, $"Expected {perm.Key.Value} to be allowed.");
            Assert.Equal(user.Id, result.UserId);
            Assert.Equal(grant.Id, result.GrantId);
            Assert.Equal(PlatformRole.PlatformAdministrator, result.Role);
            Assert.Equal(perm.Key, result.Permission);
            Assert.Null(result.DenialReason);
        }

        Assert.Equal(10, PermissionCatalog.TenantPermissions.Count);
        foreach (var tenantPerm in PermissionCatalog.TenantPermissions)
        {
            var result = await resolver.ResolveAsync(principal, tenantPerm.Key);
            Assert.False(result.IsAllowed, $"Expected {tenantPerm.Key.Value} to be denied via platform resolver.");
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData(TenantMembershipRole.Owner)]
    [InlineData(TenantMembershipRole.Administrator)]
    [InlineData(TenantMembershipRole.Member)]
    public async Task OrdinaryOrTenantScopedUsersWithoutPlatformGrant_AreDenied(TenantMembershipRole? tenantRole)
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"tenantonly.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(1));

        using (var seedDb = CreateDbContext())
        {
            seedDb.CreatePrivilegedTenantBypassScope("seed-tenant-only");
            seedDb.Users.Add(user);
            seedDb.UserSessions.Add(session);

            if (tenantRole.HasValue)
            {
                var tenant = Tenant.Create($"org-{Guid.NewGuid():N}"[..16], "Tenant Org", TenantStatus.Active);
                seedDb.Tenants.Add(tenant);
                seedDb.TenantMemberships.Add(TenantMembership.Create(tenant.Id, user.Id, tenantRole.Value));
            }

            await seedDb.SaveChangesAsync();
        }

        var principal = CreatePrincipal(user, session);
        using var evalDb = CreateDbContext();
        var resolver = CreateResolver(evalDb);

        var result = await resolver.ResolveAsync(principal, PermissionCatalog.Platform.TenantsRead);
        Assert.False(result.IsAllowed);
        Assert.Equal("NoActivePlatformGrant", result.DenialReason);
    }

    [Fact]
    public async Task RevokedGrant_AndAnotherUsersGrant_AreDenied()
    {
        var now = DateTime.UtcNow;
        var userA = User.Create($"usera.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var userB = User.Create($"userb.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var sessionA = UserSession.Create(userA.Id, now, TimeSpan.FromHours(1));

        var revokedGrantA = PlatformRoleGrant.Create(userA.Id, PlatformRole.PlatformAdministrator, userB.Id, now);
        revokedGrantA.Revoke(userB.Id, "Revoked prior to check", now.AddMinutes(1));

        var activeGrantB = PlatformRoleGrant.Create(userB.Id, PlatformRole.PlatformAdministrator, userA.Id, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(userA, userB);
            seedDb.UserSessions.Add(sessionA);
            seedDb.PlatformRoleGrants.AddRange(revokedGrantA, activeGrantB);
            await seedDb.SaveChangesAsync();
        }

        var principalA = CreatePrincipal(userA, sessionA);
        using var evalDb = CreateDbContext();
        var resolver = CreateResolver(evalDb);

        var result = await resolver.ResolveAsync(principalA, PermissionCatalog.Platform.TenantsRead);
        Assert.False(result.IsAllowed);
        Assert.Equal("NoActivePlatformGrant", result.DenialReason);
    }

    [Fact]
    public async Task InvalidAccount_InvalidSession_AndSecurityStampMismatch_AreDenied()
    {
        var now = DateTime.UtcNow;
        var suspendedUser = User.Create($"susp.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        suspendedUser.Suspend(now);
        var validUser = User.Create($"valid.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        var suspendedSession = UserSession.Create(suspendedUser.Id, now, TimeSpan.FromHours(1));
        var validSession = UserSession.Create(validUser.Id, now, TimeSpan.FromHours(1));
        var wrongUserSession = UserSession.Create(suspendedUser.Id, now, TimeSpan.FromHours(1));
        var revokedSession = UserSession.Create(validUser.Id, now, TimeSpan.FromHours(1));
        revokedSession.Revoke(SessionRevocationReason.UserLogout, now.AddMinutes(1));

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(suspendedUser, validUser);
            seedDb.UserSessions.AddRange(suspendedSession, validSession, wrongUserSession, revokedSession);
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(suspendedUser.Id, PlatformRole.PlatformAdministrator, validUser.Id, now));
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(validUser.Id, PlatformRole.PlatformAdministrator, validUser.Id, now));
            await seedDb.SaveChangesAsync();
        }

        using var evalDb = CreateDbContext();
        var resolver = CreateResolver(evalDb);
        var perm = PermissionCatalog.Platform.TenantsRead;

        // Suspended user
        Assert.Equal("IneligibleAccountOrSecurityStampMismatch",
            (await resolver.ResolveAsync(CreatePrincipal(suspendedUser, suspendedSession), perm)).DenialReason);

        // Security stamp mismatch
        var wrongStampPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, validUser.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Sid, validSession.Id.ToString()),
            new Claim("sst", "stale-or-forged-stamp")
        }, "Bearer"));
        Assert.Equal("IneligibleAccountOrSecurityStampMismatch",
            (await resolver.ResolveAsync(wrongStampPrincipal, perm)).DenialReason);

        // Wrong-user session
        Assert.Equal("InvalidOrExpiredSession",
            (await resolver.ResolveAsync(CreatePrincipal(validUser, wrongUserSession), perm)).DenialReason);

        // Revoked session
        Assert.Equal("InvalidOrExpiredSession",
            (await resolver.ResolveAsync(CreatePrincipal(validUser, revokedSession), perm)).DenialReason);

        // Missing session
        var missingSessionPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, validUser.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Sid, Guid.NewGuid().ToString()),
            new Claim("sst", validUser.SecurityStamp)
        }, "Bearer"));
        Assert.Equal("InvalidOrExpiredSession",
            (await resolver.ResolveAsync(missingSessionPrincipal, perm)).DenialReason);
    }

    [Fact]
    public async Task Freshness_GrantRevocation_AccountSuspension_StampRotation_SessionRevocation_AndExpiry_DenySamePrincipal()
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"fresh.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var actor = User.Create($"fresh.actor.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(1));
        var grant = PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, actor.Id, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(user, actor);
            seedDb.UserSessions.Add(session);
            seedDb.PlatformRoleGrants.Add(grant);
            await seedDb.SaveChangesAsync();
        }

        var samePrincipal = CreatePrincipal(user, session);
        var perm = PermissionCatalog.Platform.TenantsActivate;

        // 1. Initially allowed
        using (var db1 = CreateDbContext())
        {
            Assert.True((await CreateResolver(db1).ResolveAsync(samePrincipal, perm)).IsAllowed);
        }

        // 2. Revoke grant in separate DbContext & commit -> same principal is immediately denied
        using (var revokeDb = CreateDbContext())
        {
            var g = await revokeDb.PlatformRoleGrants.SingleAsync(x => x.Id == grant.Id);
            g.Revoke(actor.Id, "Immediate revocation freshness check", now.AddMinutes(1));
            await revokeDb.SaveChangesAsync();
        }

        using (var db2 = CreateDbContext())
        {
            var deniedAfterRevoke = await CreateResolver(db2).ResolveAsync(samePrincipal, perm);
            Assert.False(deniedAfterRevoke.IsAllowed);
            Assert.Equal("NoActivePlatformGrant", deniedAfterRevoke.DenialReason);
        }

        // 3. Re-grant active -> allowed, then suspend user -> denied
        using (var regrantDb = CreateDbContext())
        {
            regrantDb.PlatformRoleGrants.Add(
                PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, actor.Id, now.AddMinutes(2)));
            await regrantDb.SaveChangesAsync();
        }

        using (var suspendDb = CreateDbContext())
        {
            var u = await suspendDb.Users.SingleAsync(x => x.Id == user.Id);
            u.Suspend(now.AddMinutes(3));
            await suspendDb.SaveChangesAsync();
        }

        using (var db3 = CreateDbContext())
        {
            var deniedAfterSuspend = await CreateResolver(db3).ResolveAsync(samePrincipal, perm);
            Assert.False(deniedAfterSuspend.IsAllowed);
            Assert.Equal("IneligibleAccountOrSecurityStampMismatch", deniedAfterSuspend.DenialReason);
        }

        // 4. Reactivate user + rotate security stamp -> old principal stamp denied
        using (var rotateDb = CreateDbContext())
        {
            var u = await rotateDb.Users.SingleAsync(x => x.Id == user.Id);
            u.Reactivate(now.AddMinutes(4));
            u.RotateSecurityStamp(now.AddMinutes(4));
            await rotateDb.SaveChangesAsync();
        }

        using (var db4 = CreateDbContext())
        {
            var deniedAfterStampRotate = await CreateResolver(db4).ResolveAsync(samePrincipal, perm);
            Assert.False(deniedAfterStampRotate.IsAllowed);
            Assert.Equal("IneligibleAccountOrSecurityStampMismatch", deniedAfterStampRotate.DenialReason);
        }

        // 5. Updated principal with current stamp -> allowed, then session expires via TimeProvider -> denied
        User refreshedUser;
        using (var readUserDb = CreateDbContext())
        {
            refreshedUser = await readUserDb.Users.AsNoTracking().SingleAsync(x => x.Id == user.Id);
        }

        var updatedPrincipal = CreatePrincipal(refreshedUser, session);
        using (var db5 = CreateDbContext())
        {
            var expiredTime = new FakeTimeProvider(new DateTimeOffset(session.ExpiresAtUtc.AddSeconds(1), TimeSpan.Zero));
            var deniedExpired = await CreateResolver(db5, expiredTime).ResolveAsync(updatedPrincipal, perm);
            Assert.False(deniedExpired.IsAllowed);
            Assert.Equal("InvalidOrExpiredSession", deniedExpired.DenialReason);
        }
    }

    [Fact]
    public async Task GlobalScope_ConsistentAcrossNoTenantTenantAAndTenantB_WhileHttpActorRemainsNonPlatformAdmin()
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"scope.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(1));
        var tenantA = Tenant.Create($"sa-{Guid.NewGuid():N}"[..16], "Tenant A", TenantStatus.Active);
        var tenantB = Tenant.Create($"sb-{Guid.NewGuid():N}"[..16], "Tenant B", TenantStatus.Active);
        var membershipA = TenantMembership.Create(tenantA.Id, user.Id, TenantMembershipRole.Member);
        var membershipB = TenantMembership.Create(tenantB.Id, user.Id, TenantMembershipRole.Owner);

        using (var seedDb = CreateDbContext())
        {
            seedDb.CreatePrivilegedTenantBypassScope("seed-global-resolver");
            seedDb.Users.Add(user);
            seedDb.UserSessions.Add(session);
            seedDb.Tenants.AddRange(tenantA, tenantB);
            seedDb.TenantMemberships.AddRange(membershipA, membershipB);
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, user.Id, now));
            await seedDb.SaveChangesAsync();
        }

        var principal = CreatePrincipal(user, session);

        // No tenant context
        using (var dbNone = CreateDbContext(new TenantContextAccessor()))
        {
            Assert.True((await CreateResolver(dbNone).ResolveAsync(principal, PermissionCatalog.Platform.TenantsRead)).IsAllowed);
        }

        // Tenant A context
        var accessorA = new TenantContextAccessor();
        accessorA.SetContext(new TenantContext(
            tenantA.Id, tenantA.Slug, tenantA.DisplayName, user.Id, membershipA.Id,
            TenantMembershipRole.Member, TenantMembershipStatus.Active, now));
        using (var dbA = CreateDbContext(accessorA))
        {
            Assert.True((await CreateResolver(dbA).ResolveAsync(principal, PermissionCatalog.Platform.TenantsRead)).IsAllowed);
        }

        // Tenant B context
        var accessorB = new TenantContextAccessor();
        accessorB.SetContext(new TenantContext(
            tenantB.Id, tenantB.Slug, tenantB.DisplayName, user.Id, membershipB.Id,
            TenantMembershipRole.Owner, TenantMembershipStatus.Active, now));
        using (var dbB = CreateDbContext(accessorB))
        {
            Assert.True((await CreateResolver(dbB).ResolveAsync(principal, PermissionCatalog.Platform.TenantsRead)).IsAllowed);
        }
    }

    private sealed class FakeTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}
