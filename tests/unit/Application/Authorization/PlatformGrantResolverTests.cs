namespace MaintenX.UnitTests.Application.Authorization;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Application.Authorization;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Unit tests for <see cref="PlatformGrantResolver"/> covering permission validation,
/// trusted authentication boundary, claim ambiguity/malformed claim rejection,
/// cancellation propagation, fail-closed DB failure handling, and DI lifetime.
/// </summary>
public class PlatformGrantResolverTests
{
    private static PlatformGrantResolver CreateResolver(MaintenXDbContext? dbContext = null)
    {
        var context = dbContext ?? new MaintenXDbContext(
            new DbContextOptionsBuilder<MaintenXDbContext>()
                .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
                .Options);

        return new PlatformGrantResolver(
            context,
            TimeProvider.System,
            NullLogger<PlatformGrantResolver>.Instance);
    }

    private static ClaimsPrincipal CreateAuthenticatedPrincipal(
        Guid? userId = null,
        Guid? sessionId = null,
        string? securityStamp = "valid-stamp-123",
        string? authType = "Bearer")
    {
        var claims = new List<Claim>();
        if (userId.HasValue)
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, userId.Value.ToString()));
        }

        if (sessionId.HasValue)
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Sid, sessionId.Value.ToString()));
        }

        if (securityStamp is not null)
        {
            claims.Add(new Claim("sst", securityStamp));
        }

        var identity = authType is null
            ? new ClaimsIdentity(claims)
            : new ClaimsIdentity(claims, authType);

        return new ClaimsPrincipal(identity);
    }

    [Fact]
    public async Task ResolveAsync_NullOrUnregisteredOrTenantPermission_IsDenied()
    {
        var resolver = CreateResolver();
        var principal = CreateAuthenticatedPrincipal(Guid.NewGuid(), Guid.NewGuid());

        var nullResult = await resolver.ResolveAsync(principal, null);
        Assert.False(nullResult.IsAllowed);
        Assert.Equal("InvalidOrUnregisteredPlatformPermission", nullResult.DenialReason);

        var unknownResult = await resolver.ResolveAsync(principal, PermissionKey.Parse("platform.tenants.unknown"));
        Assert.False(unknownResult.IsAllowed);
        Assert.Equal("InvalidOrUnregisteredPlatformPermission", unknownResult.DenialReason);

        foreach (var tenantPerm in PermissionCatalog.TenantPermissions)
        {
            var tenantResult = await resolver.ResolveAsync(principal, tenantPerm.Key);
            Assert.False(tenantResult.IsAllowed);
            Assert.Equal("InvalidOrUnregisteredPlatformPermission", tenantResult.DenialReason);
        }
    }

    [Fact]
    public async Task ResolveAsync_UnauthenticatedOrMissingSchemePrincipal_IsDenied()
    {
        var resolver = CreateResolver();
        var perm = PermissionCatalog.Platform.TenantsRead;

        var nullPrincipal = await resolver.ResolveAsync(null, perm);
        Assert.False(nullPrincipal.IsAllowed);
        Assert.Equal("UnauthenticatedPrincipal", nullPrincipal.DenialReason);

        var unauthPrincipal = CreateAuthenticatedPrincipal(Guid.NewGuid(), Guid.NewGuid(), authType: null);
        var unauthResult = await resolver.ResolveAsync(unauthPrincipal, perm);
        Assert.False(unauthResult.IsAllowed);
        Assert.Equal("UnauthenticatedPrincipal", unauthResult.DenialReason);

        var emptyAuthTypeIdentity = new ClaimsIdentity(
            new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sid, Guid.NewGuid().ToString()),
                new Claim("sst", "stamp")
            },
            authenticationType: "");
        var emptyAuthTypeResult = await resolver.ResolveAsync(new ClaimsPrincipal(emptyAuthTypeIdentity), perm);
        Assert.False(emptyAuthTypeResult.IsAllowed);
        Assert.Equal("UnauthenticatedPrincipal", emptyAuthTypeResult.DenialReason);
    }

    [Fact]
    public async Task ResolveAsync_MissingEmptyMalformedOrAmbiguousClaims_IsDenied()
    {
        var resolver = CreateResolver();
        var perm = PermissionCatalog.Platform.TenantsRead;

        // Missing / empty / malformed sub
        Assert.Equal("InvalidOrAmbiguousUserClaim",
            (await resolver.ResolveAsync(CreateAuthenticatedPrincipal(null, Guid.NewGuid()), perm)).DenialReason);
        Assert.Equal("InvalidOrAmbiguousUserClaim",
            (await resolver.ResolveAsync(CreateAuthenticatedPrincipal(Guid.Empty, Guid.NewGuid()), perm)).DenialReason);

        var malformedSub = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("sub", "not-a-guid"),
            new Claim("sid", Guid.NewGuid().ToString()),
            new Claim("sst", "stamp")
        }, "Bearer"));
        Assert.Equal("InvalidOrAmbiguousUserClaim", (await resolver.ResolveAsync(malformedSub, perm)).DenialReason);

        // Ambiguous duplicate sub
        var dupSub = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("sid", Guid.NewGuid().ToString()),
            new Claim("sst", "stamp")
        }, "Bearer"));
        Assert.Equal("InvalidOrAmbiguousUserClaim", (await resolver.ResolveAsync(dupSub, perm)).DenialReason);

        // Missing / empty / ambiguous sid
        Assert.Equal("InvalidOrAmbiguousSessionClaim",
            (await resolver.ResolveAsync(CreateAuthenticatedPrincipal(Guid.NewGuid(), null), perm)).DenialReason);
        Assert.Equal("InvalidOrAmbiguousSessionClaim",
            (await resolver.ResolveAsync(CreateAuthenticatedPrincipal(Guid.NewGuid(), Guid.Empty), perm)).DenialReason);

        var dupSid = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("sid", Guid.NewGuid().ToString()),
            new Claim("sid", Guid.NewGuid().ToString()),
            new Claim("sst", "stamp")
        }, "Bearer"));
        Assert.Equal("InvalidOrAmbiguousSessionClaim", (await resolver.ResolveAsync(dupSid, perm)).DenialReason);

        // Missing / whitespace / ambiguous sst
        Assert.Equal("InvalidOrAmbiguousSecurityStampClaim",
            (await resolver.ResolveAsync(CreateAuthenticatedPrincipal(Guid.NewGuid(), Guid.NewGuid(), null), perm)).DenialReason);
        Assert.Equal("InvalidOrAmbiguousSecurityStampClaim",
            (await resolver.ResolveAsync(CreateAuthenticatedPrincipal(Guid.NewGuid(), Guid.NewGuid(), "   "), perm)).DenialReason);

        var dupSst = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("sid", Guid.NewGuid().ToString()),
            new Claim("sst", "stamp-1"),
            new Claim("sst", "stamp-2")
        }, "Bearer"));
        Assert.Equal("InvalidOrAmbiguousSecurityStampClaim", (await resolver.ResolveAsync(dupSst, perm)).DenialReason);
    }

    [Fact]
    public async Task ResolveAsync_ClientSuppliedRoleOrAdminClaimWithoutTrustedIdentity_CannotElevate()
    {
        var resolver = CreateResolver();
        var unauthWithRoleClaims = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Role, "PlatformAdministrator"),
            new Claim("IsPlatformAdmin", "true")
        }));

        var result = await resolver.ResolveAsync(unauthWithRoleClaims, PermissionCatalog.Platform.TenantsActivate);
        Assert.False(result.IsAllowed);
        Assert.Null(result.UserId);
        Assert.Null(result.GrantId);
        Assert.Null(result.Role);
    }

    [Fact]
    public async Task ResolveAsync_PreCancelledToken_ThrowsOperationCanceledException()
    {
        var resolver = CreateResolver();
        var principal = CreateAuthenticatedPrincipal(Guid.NewGuid(), Guid.NewGuid());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            resolver.ResolveAsync(principal, PermissionCatalog.Platform.TenantsRead, cts.Token));
    }

    [Fact]
    public async Task ResolveAsync_DatabaseFailure_FailsClosedWithNoAllowingDecision()
    {
        var disposedContext = new MaintenXDbContext(
            new DbContextOptionsBuilder<MaintenXDbContext>()
                .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
                .Options);
        await disposedContext.DisposeAsync();

        var resolver = CreateResolver(disposedContext);
        var principal = CreateAuthenticatedPrincipal(Guid.NewGuid(), Guid.NewGuid());

        var result = await resolver.ResolveAsync(principal, PermissionCatalog.Platform.TenantsRead);
        Assert.False(result.IsAllowed);
        Assert.Equal("InfrastructureFailure", result.DenialReason);
    }

    [Fact]
    public void AddMaintenXAuthorization_RegistersScopedResolver()
    {
        var services = new ServiceCollection();
        services.AddMaintenXAuthorization();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IPlatformGrantResolver));
        Assert.Equal(typeof(PlatformGrantResolver), descriptor.ImplementationType);
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
    }
}
