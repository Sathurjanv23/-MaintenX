namespace MaintenX.IntegrationTests;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Resolution;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using SecurityStampValidator = MaintenX.Api.Common.Security.SecurityStampValidator;

/// <summary>
/// Integration test suite for FEAT-003 Task 3.6.1 Tenant API Foundation &amp; Trusted Actor Resolution.
/// Runs against a disposable, isolated PostgreSQL 16 database.
/// Validates server-side session non-revocation enforcement, security stamp validation against real database rows,
/// tenant-neutral authenticated actor resolution, verified tenant-scoped actor resolution, and platform-admin forgery prevention.
/// </summary>
public class TenantActorResolutionIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public TenantActorResolutionIntegrationTests()
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

    private MaintenXDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return new MaintenXDbContext(options);
    }

    private static ClaimsPrincipal CreatePrincipal(
        Guid userId,
        Guid sessionId,
        string securityStamp,
        string? roleClaim = null)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new("sid", sessionId.ToString()),
            new("sst", securityStamp)
        };

        if (roleClaim != null)
        {
            claims.Add(new Claim(ClaimTypes.Role, roleClaim));
            claims.Add(new Claim("is_platform_admin", "true")); // Forged claim test
        }

        var identity = new ClaimsIdentity(claims, "Bearer");
        return new ClaimsPrincipal(identity);
    }

    private async Task<(User User, UserSession Session)> SeedUserAndSessionAsync(bool isSessionRevoked = false)
    {
        using var context = CreateContext();
        var now = DateTime.UtcNow;

        var user = User.Create($"actor_integ_{Guid.NewGuid():N}@maintenx.dev", "hash_secret", UserStatus.Active, now);
        context.Users.Add(user);

        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(1));
        if (isSessionRevoked)
        {
            session.Revoke(SessionRevocationReason.UserLogout, now);
        }
        context.UserSessions.Add(session);

        await context.SaveChangesAsync();
        return (user, session);
    }

    private SecurityStampValidator CreateStampValidator(MaintenXDbContext context)
    {
        var stampStore = new EfUserSecurityStampStore(context);
        var memoryCache = new MemoryCache(new MemoryCacheOptions());
        return new SecurityStampValidator(stampStore, memoryCache, NullLogger<SecurityStampValidator>.Instance);
    }

    [Fact]
    public async Task ResolveActorAsync_ActiveUserAndSession_TenantNeutral_ReturnsTrustedActorWithoutPlatformAdmin()
    {
        var (user, session) = await SeedUserAndSessionAsync();
        using var context = CreateContext();

        var stampValidator = CreateStampValidator(context);
        var contextAccessor = new TenantContextAccessor();

        var resolver = new TenantActorResolver(
            context,
            stampValidator,
            contextAccessor,
            TimeProvider.System,
            NullLogger<TenantActorResolver>.Instance);

        var principal = CreatePrincipal(user.Id, session.Id, user.SecurityStamp, roleClaim: "PlatformAdmin");

        var result = await resolver.ResolveActorAsync(principal, requireActiveTenantContext: false);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Actor);
        Assert.Equal(user.Id, result.Actor.UserId);
        Assert.False(result.Actor.IsPlatformAdmin); // Invariant: ordinary HTTP callers are NEVER platform admin
        Assert.Null(result.Actor.TenantId);
        Assert.Null(result.Actor.Role);
    }

    [Fact]
    public async Task ResolveActorAsync_RevokedSession_FailsWith401Unauthorized()
    {
        var (user, session) = await SeedUserAndSessionAsync(isSessionRevoked: true);
        using var context = CreateContext();

        var stampValidator = CreateStampValidator(context);
        var contextAccessor = new TenantContextAccessor();

        var resolver = new TenantActorResolver(
            context,
            stampValidator,
            contextAccessor,
            TimeProvider.System,
            NullLogger<TenantActorResolver>.Instance);

        var principal = CreatePrincipal(user.Id, session.Id, user.SecurityStamp);

        var result = await resolver.ResolveActorAsync(principal, requireActiveTenantContext: false);

        Assert.False(result.IsSuccess);
        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
        Assert.Contains("expired, revoked, or invalid", result.ErrorDetail);
    }

    [Fact]
    public async Task ResolveActorAsync_TamperedSecurityStamp_FailsWith401Unauthorized()
    {
        var (user, session) = await SeedUserAndSessionAsync();
        using var context = CreateContext();

        var stampValidator = CreateStampValidator(context);
        var contextAccessor = new TenantContextAccessor();

        var resolver = new TenantActorResolver(
            context,
            stampValidator,
            contextAccessor,
            TimeProvider.System,
            NullLogger<TenantActorResolver>.Instance);

        var principal = CreatePrincipal(user.Id, session.Id, "tampered-stamp-value");

        var result = await resolver.ResolveActorAsync(principal, requireActiveTenantContext: false);

        Assert.False(result.IsSuccess);
        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
        Assert.Contains("Security credentials or user account status are no longer valid", result.ErrorDetail);
    }

    [Fact]
    public async Task ResolveActorAsync_RequireActiveTenant_WithVerifiedTenantContext_DerivesTenantScopedActor()
    {
        var (user, session) = await SeedUserAndSessionAsync();
        using var context = CreateContext();

        var tenant = Tenant.Create("actor-integ-slug", "Actor Integration Org", TenantStatus.Active);
        context.Tenants.Add(tenant);

        var membership = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Owner, TenantMembershipStatus.Active);
        using (context.CreatePrivilegedTenantBypassScope("seed-test-data"))
        {
            context.TenantMemberships.Add(membership);
            await context.SaveChangesAsync();
        }

        var stampValidator = CreateStampValidator(context);
        var contextAccessor = new TenantContextAccessor();

        // Establish verified tenant context in accessor
        contextAccessor.SetContext(new TenantContext(
            tenant.Id,
            tenant.Slug,
            tenant.DisplayName,
            user.Id,
            membership.Id,
            TenantMembershipRole.Owner,
            TenantMembershipStatus.Active,
            DateTime.UtcNow));

        var resolver = new TenantActorResolver(
            context,
            stampValidator,
            contextAccessor,
            TimeProvider.System,
            NullLogger<TenantActorResolver>.Instance);

        var principal = CreatePrincipal(user.Id, session.Id, user.SecurityStamp);

        var result = await resolver.ResolveActorAsync(principal, requireActiveTenantContext: true);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Actor);
        Assert.Equal(user.Id, result.Actor.UserId);
        Assert.Equal(tenant.Id, result.Actor.TenantId);
        Assert.Equal(TenantMembershipRole.Owner, result.Actor.Role);
        Assert.False(result.Actor.IsPlatformAdmin);
    }
}
