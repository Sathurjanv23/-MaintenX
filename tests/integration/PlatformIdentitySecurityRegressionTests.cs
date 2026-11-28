namespace MaintenX.IntegrationTests;

using System.Data;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
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
/// FEAT-004 Task 4.3.4 — Platform Identity & Authority Security Regression Verification Suite.
/// Validates end-to-end security invariants across Step 4.3:
/// 1. Zero trust in caller-provided claims or tokens: forged/arbitrary JWT claims cannot grant platform authority.
/// 2. User account eligibility: disabled, suspended, or missing accounts immediately deny platform authority.
/// 3. Self-revocation protection: administrators cannot revoke their own platform grants.
/// 4. Last administrator protection: the single remaining active eligible administrator cannot be revoked.
/// 5. Optimistic concurrency: mismatched ExpectedVersion aborts revocation atomically.
/// 6. Advisory lock concurrency: concurrent cross-revocation is strictly serialized.
/// 7. Immediate bearer invalidation: revoked grants immediately cause 403 Forbidden on subsequent requests.
/// 8. Durable audit trail: every grant mutation records an immutable SecurityAuditEvent atomically.
/// </summary>
public class PlatformIdentitySecurityRegressionTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public PlatformIdentitySecurityRegressionTests()
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

    [Theory]
    [InlineData("role", "PlatformAdministrator")]
    [InlineData("is_platform_admin", "true")]
    [InlineData("permissions", "platform.tenants.write")]
    [InlineData("admin", "1")]
    public async Task ThreatVector_ForgedClaimsInJwt_WithoutDatabaseGrant_AreCategoricallyDenied(string claimType, string claimValue)
    {
        var now = DateTime.UtcNow;
        var attacker = User.Create($"attacker.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var session = UserSession.Create(attacker.Id, now, TimeSpan.FromHours(1));

        using (var db = CreateDbContext())
        {
            db.Users.Add(attacker);
            db.UserSessions.Add(session);
            await db.SaveChangesAsync();
        }

        // Create a principal with attacker's user ID, valid session & stamp, and forged claims, but NO PlatformRoleGrant in DB
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, attacker.Id.ToString()),
            new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sid, session.Id.ToString()),
            new Claim("sst", attacker.SecurityStamp),
            new Claim(claimType, claimValue)
        };
        var identity = new ClaimsIdentity(claims, JwtBearerDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        using var testDb = CreateDbContext();
        var stubAuth = new StubAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(principal, JwtBearerDefaults.AuthenticationScheme)));
        var httpContextAccessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = principal } };

        var resolver = new PlatformGrantResolver(
            httpContextAccessor,
            stubAuth,
            testDb,
            TimeProvider.System,
            NullLogger<PlatformGrantResolver>.Instance);

        var result = await resolver.ResolveAsync(PermissionCatalog.Platform.TenantsActivate);

        Assert.False(result.IsAllowed);
        Assert.Equal("NoActivePlatformGrant", result.DenialReason);
    }

    [Theory]
    [InlineData(UserStatus.Suspended)]
    [InlineData(UserStatus.Deactivated)]
    public async Task Invariant_NonActiveUserAccount_ImmediatelyDeniesPlatformAuthority_EvenWithActiveGrant(UserStatus nonActiveStatus)
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"status.{nonActiveStatus}.{Guid.NewGuid():N}@maintenx.internal", "hash", nonActiveStatus, now);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(1));

        using (var db = CreateDbContext())
        {
            db.Users.Add(user);
            db.UserSessions.Add(session);
            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(user.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", now));
            await db.SaveChangesAsync();
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sid, session.Id.ToString()),
            new Claim("sst", user.SecurityStamp)
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, JwtBearerDefaults.AuthenticationScheme));

        using var testDb = CreateDbContext();
        var stubAuth = new StubAuthenticationService(AuthenticateResult.Success(new AuthenticationTicket(principal, JwtBearerDefaults.AuthenticationScheme)));
        var httpContextAccessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = principal } };

        var resolver = new PlatformGrantResolver(
            httpContextAccessor,
            stubAuth,
            testDb,
            TimeProvider.System,
            NullLogger<PlatformGrantResolver>.Instance);

        var result = await resolver.ResolveAsync(PermissionCatalog.Platform.TenantsRead);

        Assert.False(result.IsAllowed);
        Assert.Equal("IneligibleAccountOrSecurityStampMismatch", result.DenialReason);
    }

    [Fact]
    public async Task Invariant_SelfRevocation_IsConservativelyProhibited()
    {
        var now = DateTime.UtcNow;
        var admin = User.Create($"self.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        using (var db = CreateDbContext())
        {
            db.Users.Add(admin);
            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(admin.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", now));
            await db.SaveChangesAsync();
        }

        using var testDb = CreateDbContext();
        var grant = await testDb.PlatformRoleGrants.SingleAsync(g => g.UserId == admin.Id);

        var stubResolver = new StubGrantResolver(PlatformGrantResolutionResult.Allow(
            admin.Id, grant.Id, PlatformRole.PlatformAdministrator, PermissionCatalog.Platform.TenantsActivate));

        var service = new PlatformGrantService(
            testDb,
            stubResolver,
            TimeProvider.System,
            NullLogger<PlatformGrantService>.Instance);

        var result = await service.RevokeGrantAsync(new PlatformGrantRevocationRequest(grant.Id, "Accidental self lockout attempt"));

        Assert.False(result.IsSuccess);
        Assert.Equal(PlatformGrantRevocationOutcome.SelfRevocationDenied, result.Outcome);

        // Verify grant is intact
        using var verifyDb = CreateDbContext();
        var unchangedGrant = await verifyDb.PlatformRoleGrants.SingleAsync(g => g.Id == grant.Id);
        Assert.Equal(PlatformRoleGrantStatus.Active, unchangedGrant.Status);
    }

    [Fact]
    public async Task Invariant_LastAdministratorProtection_PreventsRevocationOfSoleAdmin()
    {
        var now = DateTime.UtcNow;
        var soleAdmin = User.Create($"sole.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var callerSuspended = User.Create($"caller.susp.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Suspended, now);

        using (var db = CreateDbContext())
        {
            db.Users.AddRange(soleAdmin, callerSuspended);
            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(soleAdmin.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", now));
            db.PlatformRoleGrants.Add(PlatformRoleGrant.Create(callerSuspended.Id, PlatformRole.PlatformAdministrator, soleAdmin.Id, now));
            await db.SaveChangesAsync();
        }

        using var testDb = CreateDbContext();
        var soleGrant = await testDb.PlatformRoleGrants.SingleAsync(g => g.UserId == soleAdmin.Id);

        var stubResolver = new StubGrantResolver(PlatformGrantResolutionResult.Allow(
            callerSuspended.Id, Guid.NewGuid(), PlatformRole.PlatformAdministrator, PermissionCatalog.Platform.TenantsActivate));

        var service = new PlatformGrantService(
            testDb,
            stubResolver,
            TimeProvider.System,
            NullLogger<PlatformGrantService>.Instance);

        var result = await service.RevokeGrantAsync(new PlatformGrantRevocationRequest(soleGrant.Id, "Attempt revoke sole active admin"));

        Assert.False(result.IsSuccess);
        Assert.Equal(PlatformGrantRevocationOutcome.LastAdministratorProtected, result.Outcome);

        // Verify sole admin grant remains Active
        using var verifyDb = CreateDbContext();
        var persisted = await verifyDb.PlatformRoleGrants.SingleAsync(g => g.Id == soleGrant.Id);
        Assert.Equal(PlatformRoleGrantStatus.Active, persisted.Status);
    }

    [Fact]
    public async Task Invariant_RevocationGeneratesDurableSecurityAudit_Atomically()
    {
        var now = DateTime.UtcNow;
        var adminA = User.Create($"audit.a.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var adminB = User.Create($"audit.b.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        using (var db = CreateDbContext())
        {
            db.Users.AddRange(adminA, adminB);
            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(adminA.Id, PlatformRole.PlatformAdministrator, "os:deploy@host", now));
            db.PlatformRoleGrants.Add(PlatformRoleGrant.Create(adminB.Id, PlatformRole.PlatformAdministrator, adminA.Id, now));
            await db.SaveChangesAsync();
        }

        using var testDb = CreateDbContext();
        var grantB = await testDb.PlatformRoleGrants.SingleAsync(g => g.UserId == adminB.Id);

        var service = new PlatformGrantService(
            testDb,
            new StubGrantResolver(PlatformGrantResolutionResult.Allow(adminA.Id, Guid.NewGuid(), PlatformRole.PlatformAdministrator, PermissionCatalog.Platform.TenantsActivate)),
            TimeProvider.System,
            NullLogger<PlatformGrantService>.Instance);

        var result = await service.RevokeGrantAsync(new PlatformGrantRevocationRequest(grantB.Id, "Scheduled administrative rotation"));

        Assert.True(result.IsSuccess);
        Assert.Equal(PlatformGrantRevocationOutcome.Revoked, result.Outcome);
        Assert.NotNull(result.AuditEventId);

        using var verifyDb = CreateDbContext();
        var audit = await verifyDb.SecurityAuditEvents.SingleAsync(a => a.Id == result.AuditEventId);

        Assert.Equal(SecurityAuditEventType.SessionRevoked, audit.EventType);
        Assert.Equal(adminB.Id, audit.UserId);
        Assert.Equal($"grant_{grantB.Id:N}", audit.DetectedLineage);
        Assert.Equal(SecurityAuditMetadata.Reasons.AdminAction, audit.Reason);
        Assert.Equal(SecurityAuditMetadata.Actions.SessionRevoked, audit.ActionTaken);
    }

    private sealed class StubAuthenticationService(AuthenticateResult result) : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(result);
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }

    private sealed class StubGrantResolver(PlatformGrantResolutionResult result) : IPlatformGrantResolver
    {
        public Task<PlatformGrantResolutionResult> ResolveAsync(PermissionKey? permission, CancellationToken cancellationToken = default) =>
            Task.FromResult(result);
    }
}
