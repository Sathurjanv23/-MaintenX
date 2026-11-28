namespace MaintenX.UnitTests.Application.Authorization;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Application.Authorization;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Unit tests for <see cref="PlatformGrantResolver"/> covering server-controlled Bearer
/// authentication provenance, untrusted scheme/manual HttpContext.User rejection,
/// multi-identity ambiguity, claim validation, cancellation, DB failure handling, and DI lifetime.
/// </summary>
public class PlatformGrantResolverTests
{
    private static PlatformGrantResolver CreateResolver(
        HttpContext? httpContext,
        IAuthenticationService? authService = null,
        MaintenXDbContext? dbContext = null)
    {
        var accessor = new HttpContextAccessor { HttpContext = httpContext };
        var context = dbContext ?? new MaintenXDbContext(
            new DbContextOptionsBuilder<MaintenXDbContext>()
                .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
                .Options);

        return new PlatformGrantResolver(
            accessor,
            authService ?? new StubAuthenticationService(AuthenticateResult.NoResult()),
            context,
            TimeProvider.System,
            NullLogger<PlatformGrantResolver>.Instance);
    }

    private static ClaimsPrincipal CreatePrincipal(
        Guid? userId = null,
        Guid? sessionId = null,
        string? securityStamp = "valid-stamp-123",
        string? authType = JwtBearerDefaults.AuthenticationScheme)
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
    public void Interface_DoesNotExposeCallerSuppliedPrincipalOverload()
    {
        var methods = typeof(IPlatformGrantResolver).GetMethods();
        var singleMethod = Assert.Single(methods);
        Assert.Equal("ResolveAsync", singleMethod.Name);
        Assert.DoesNotContain(singleMethod.GetParameters(), p => p.ParameterType == typeof(ClaimsPrincipal));
    }

    [Fact]
    public async Task ResolveAsync_NullOrUnregisteredOrTenantPermission_IsDenied()
    {
        var httpContext = new DefaultHttpContext();
        var principal = CreatePrincipal(Guid.NewGuid(), Guid.NewGuid());
        var auth = new StubAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(principal, JwtBearerDefaults.AuthenticationScheme)));
        var resolver = CreateResolver(httpContext, auth);

        var nullResult = await resolver.ResolveAsync(null);
        Assert.False(nullResult.IsAllowed);
        Assert.Equal("InvalidOrUnregisteredPlatformPermission", nullResult.DenialReason);

        var unknownResult = await resolver.ResolveAsync(PermissionKey.Parse("platform.tenants.unknown"));
        Assert.False(unknownResult.IsAllowed);
        Assert.Equal("InvalidOrUnregisteredPlatformPermission", unknownResult.DenialReason);

        foreach (var tenantPerm in PermissionCatalog.TenantPermissions)
        {
            var tenantResult = await resolver.ResolveAsync(tenantPerm.Key);
            Assert.False(tenantResult.IsAllowed);
            Assert.Equal("InvalidOrUnregisteredPlatformPermission", tenantResult.DenialReason);
        }
    }

    [Fact]
    public async Task ResolveAsync_MissingHttpContext_OrNoResult_OrFailure_IsDenied()
    {
        var perm = PermissionCatalog.Platform.TenantsRead;

        // A. No current HTTP context
        var noContextResult = await CreateResolver(null).ResolveAsync(perm);
        Assert.False(noContextResult.IsAllowed);
        Assert.Equal("MissingHttpContext", noContextResult.DenialReason);

        // B. AuthenticateAsync returns NoResult
        var noResult = await CreateResolver(
            new DefaultHttpContext(),
            new StubAuthenticationService(AuthenticateResult.NoResult())).ResolveAsync(perm);
        Assert.False(noResult.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", noResult.DenialReason);

        // C. AuthenticateAsync returns Fail
        var failResult = await CreateResolver(
            new DefaultHttpContext(),
            new StubAuthenticationService(AuthenticateResult.Fail("Invalid signature"))).ResolveAsync(perm);
        Assert.False(failResult.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", failResult.DenialReason);
    }

    [Fact]
    public async Task ResolveAsync_ManuallyAssignedHttpContextUser_WithoutBearerSuccess_IsDenied()
    {
        var httpContext = new DefaultHttpContext
        {
            User = CreatePrincipal(Guid.NewGuid(), Guid.NewGuid())
        };

        var resolver = CreateResolver(httpContext, new StubAuthenticationService(AuthenticateResult.NoResult()));
        var result = await resolver.ResolveAsync(PermissionCatalog.Platform.TenantsRead);

        Assert.False(result.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", result.DenialReason);
    }

    [Fact]
    public async Task ResolveAsync_UntrustedAuthenticationScheme_IsDenied()
    {
        var principal = CreatePrincipal(Guid.NewGuid(), Guid.NewGuid(), authType: "CustomScheme");
        var auth = new StubAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(principal, "CustomScheme")));

        var resolver = CreateResolver(new DefaultHttpContext(), auth);
        var result = await resolver.ResolveAsync(PermissionCatalog.Platform.TenantsRead);

        Assert.False(result.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", result.DenialReason);
    }

    [Fact]
    public async Task ResolveAsync_MultipleAuthenticatedIdentities_IsDenied()
    {
        var id1 = new ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sid, Guid.NewGuid().ToString()),
            new Claim("sst", "stamp-1")
        }, JwtBearerDefaults.AuthenticationScheme);

        var id2 = new ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Sid, Guid.NewGuid().ToString()),
            new Claim("sst", "stamp-2")
        }, JwtBearerDefaults.AuthenticationScheme);

        var principal = new ClaimsPrincipal(new[] { id1, id2 });
        var auth = new StubAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(principal, JwtBearerDefaults.AuthenticationScheme)));

        var resolver = CreateResolver(new DefaultHttpContext(), auth);
        var result = await resolver.ResolveAsync(PermissionCatalog.Platform.TenantsRead);

        Assert.False(result.IsAllowed);
        Assert.Equal("AmbiguousAuthenticatedIdentities", result.DenialReason);
    }

    [Fact]
    public async Task ResolveAsync_MissingEmptyMalformedOrAmbiguousClaims_IsDenied()
    {
        var perm = PermissionCatalog.Platform.TenantsRead;

        async Task<string?> Eval(ClaimsPrincipal p)
        {
            var auth = new StubAuthenticationService(
                AuthenticateResult.Success(new AuthenticationTicket(p, JwtBearerDefaults.AuthenticationScheme)));
            return (await CreateResolver(new DefaultHttpContext(), auth).ResolveAsync(perm)).DenialReason;
        }

        Assert.Equal("InvalidOrAmbiguousUserClaim", await Eval(CreatePrincipal(null, Guid.NewGuid())));
        Assert.Equal("InvalidOrAmbiguousUserClaim", await Eval(CreatePrincipal(Guid.Empty, Guid.NewGuid())));

        var dupSub = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("sid", Guid.NewGuid().ToString()),
            new Claim("sst", "stamp")
        }, JwtBearerDefaults.AuthenticationScheme));
        Assert.Equal("InvalidOrAmbiguousUserClaim", await Eval(dupSub));

        Assert.Equal("InvalidOrAmbiguousSessionClaim", await Eval(CreatePrincipal(Guid.NewGuid(), null)));
        Assert.Equal("InvalidOrAmbiguousSessionClaim", await Eval(CreatePrincipal(Guid.NewGuid(), Guid.Empty)));

        Assert.Equal("InvalidOrAmbiguousSecurityStampClaim", await Eval(CreatePrincipal(Guid.NewGuid(), Guid.NewGuid(), null)));
        Assert.Equal("InvalidOrAmbiguousSecurityStampClaim", await Eval(CreatePrincipal(Guid.NewGuid(), Guid.NewGuid(), "   ")));
    }

    [Fact]
    public async Task ResolveAsync_PreCancelledToken_ThrowsOperationCanceledException()
    {
        var resolver = CreateResolver(new DefaultHttpContext());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            resolver.ResolveAsync(PermissionCatalog.Platform.TenantsRead, cts.Token));
    }

    [Fact]
    public async Task ResolveAsync_DatabaseFailure_FailsClosedWithNoAllowingDecision()
    {
        var disposedContext = new MaintenXDbContext(
            new DbContextOptionsBuilder<MaintenXDbContext>()
                .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
                .Options);
        await disposedContext.DisposeAsync();

        var principal = CreatePrincipal(Guid.NewGuid(), Guid.NewGuid());
        var auth = new StubAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(principal, JwtBearerDefaults.AuthenticationScheme)));

        var resolver = CreateResolver(new DefaultHttpContext(), auth, disposedContext);
        var result = await resolver.ResolveAsync(PermissionCatalog.Platform.TenantsRead);

        Assert.False(result.IsAllowed);
        Assert.Equal("InfrastructureFailure", result.DenialReason);
    }

    [Fact]
    public void AddMaintenXAuthorization_RegistersHttpContextAccessorAndScopedResolver()
    {
        var services = new ServiceCollection();
        services.AddMaintenXAuthorization();

        Assert.Contains(services, d => d.ServiceType == typeof(IHttpContextAccessor));
        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IPlatformGrantResolver));
        Assert.Equal(typeof(PlatformGrantResolver), descriptor.ImplementationType);
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);

        var grantServiceDesc = Assert.Single(services, d => d.ServiceType == typeof(IPlatformGrantService));
        Assert.Equal(typeof(PlatformGrantService), grantServiceDesc.ImplementationType);
        Assert.Equal(ServiceLifetime.Scoped, grantServiceDesc.Lifetime);
    }

    private sealed class StubAuthenticationService(AuthenticateResult result) : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(string.Equals(scheme, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal)
                ? result
                : AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            Task.CompletedTask;
    }
}
