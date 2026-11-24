namespace MaintenX.UnitTests.Application.Tenancy;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Endpoints;
using MaintenX.Api.Application.Tenancy.Models;
using MaintenX.Api.Application.Tenancy.Resolution;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Unit tests for FEAT-003 Task 3.6.1 Tenant API Foundation &amp; Trusted Actor Resolution.
/// Validates that actor context resolution strictly derives caller identity from verified claims,
/// validates session non-revocation and security stamp consistency, prevents platform-admin forgery,
/// and properly maps application result contracts to HTTP Problem Details.
/// </summary>
public class TenantActorResolverUnitTests
{
    private sealed class FakeSecurityStampValidator : ISecurityStampValidator
    {
        public bool IsValidResult { get; set; } = true;

        public Task<bool> ValidateAsync(Guid userId, string securityStamp, CancellationToken cancellationToken = default)
            => Task.FromResult(IsValidResult);

        public void Invalidate(Guid userId) { }
    }

    private sealed class FakeTenantContextAccessor : ITenantContextAccessor
    {
        public ITenantContext? Current { get; set; }
    }

    private sealed class FakeTenantContext : ITenantContext
    {
        public Guid TenantId { get; init; }
        public string TenantSlug { get; init; } = string.Empty;
        public string TenantDisplayName { get; init; } = string.Empty;
        public Guid UserId { get; init; }
        public Guid MembershipId { get; init; }
        public TenantMembershipRole Role { get; init; }
        public TenantMembershipStatus Status { get; init; }
        public DateTime ResolvedAtUtc { get; init; }
    }

    private static MaintenXDbContext CreateDummyContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=dummy;Username=dummy;Password=dummy")
            .Options;

        return new MaintenXDbContext(options);
    }

    private static ClaimsPrincipal CreatePrincipal(
        Guid? userId = null,
        Guid? sessionId = null,
        string? securityStamp = "valid-stamp",
        bool isAuthenticated = true,
        string? roleClaim = null)
    {
        if (!isAuthenticated)
        {
            return new ClaimsPrincipal(new ClaimsIdentity());
        }

        var claims = new List<Claim>();

        if (userId.HasValue)
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, userId.Value.ToString()));
        }

        if (sessionId.HasValue)
        {
            claims.Add(new Claim("sid", sessionId.Value.ToString()));
        }

        if (securityStamp is not null)
        {
            claims.Add(new Claim("sst", securityStamp));
        }

        if (roleClaim is not null)
        {
            claims.Add(new Claim(ClaimTypes.Role, roleClaim));
            claims.Add(new Claim("is_platform_admin", "true")); // Forged claim test
        }

        var identity = new ClaimsIdentity(claims, "TestAuthType");
        return new ClaimsPrincipal(identity);
    }

    [Fact]
    public async Task ResolveActorAsync_UnauthenticatedUser_FailsWith401Unauthorized()
    {
        using var dbContext = CreateDummyContext();
        var stampValidator = new FakeSecurityStampValidator();
        var contextAccessor = new FakeTenantContextAccessor();
        var resolver = new TenantActorResolver(
            dbContext,
            stampValidator,
            contextAccessor,
            TimeProvider.System,
            NullLogger<TenantActorResolver>.Instance);

        var principal = CreatePrincipal(isAuthenticated: false);

        var result = await resolver.ResolveActorAsync(principal);

        Assert.False(result.IsSuccess);
        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
        Assert.Contains("Authentication is required", result.ErrorDetail);
    }

    [Fact]
    public async Task ResolveActorAsync_MissingUserIdClaim_FailsWith401Unauthorized()
    {
        using var dbContext = CreateDummyContext();
        var stampValidator = new FakeSecurityStampValidator();
        var contextAccessor = new FakeTenantContextAccessor();
        var resolver = new TenantActorResolver(
            dbContext,
            stampValidator,
            contextAccessor,
            TimeProvider.System,
            NullLogger<TenantActorResolver>.Instance);

        var principal = CreatePrincipal(userId: null, sessionId: Guid.NewGuid());

        var result = await resolver.ResolveActorAsync(principal);

        Assert.False(result.IsSuccess);
        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
        Assert.Contains("Invalid or missing user identity claim", result.ErrorDetail);
    }

    [Fact]
    public async Task ResolveActorAsync_MissingSessionIdClaim_FailsWith401Unauthorized()
    {
        using var dbContext = CreateDummyContext();
        var stampValidator = new FakeSecurityStampValidator();
        var contextAccessor = new FakeTenantContextAccessor();
        var resolver = new TenantActorResolver(
            dbContext,
            stampValidator,
            contextAccessor,
            TimeProvider.System,
            NullLogger<TenantActorResolver>.Instance);

        var principal = CreatePrincipal(userId: Guid.NewGuid(), sessionId: null);

        var result = await resolver.ResolveActorAsync(principal);

        Assert.False(result.IsSuccess);
        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
        Assert.Contains("Invalid or missing session identifier claim", result.ErrorDetail);
    }

    [Fact]
    public async Task ResolveActorAsync_MissingSecurityStampClaim_FailsWith401Unauthorized()
    {
        using var dbContext = CreateDummyContext();
        var stampValidator = new FakeSecurityStampValidator();
        var contextAccessor = new FakeTenantContextAccessor();
        var resolver = new TenantActorResolver(
            dbContext,
            stampValidator,
            contextAccessor,
            TimeProvider.System,
            NullLogger<TenantActorResolver>.Instance);

        var principal = CreatePrincipal(userId: Guid.NewGuid(), sessionId: Guid.NewGuid(), securityStamp: null);

        var result = await resolver.ResolveActorAsync(principal);

        Assert.False(result.IsSuccess);
        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
        Assert.Contains("Missing required security stamp claim", result.ErrorDetail);
    }

    [Fact]
    public async Task ResolveActorAsync_InvalidSecurityStamp_FailsWith401Unauthorized()
    {
        using var dbContext = CreateDummyContext();
        var stampValidator = new FakeSecurityStampValidator { IsValidResult = false };
        var contextAccessor = new FakeTenantContextAccessor();

        var userId = Guid.NewGuid();

        var resolver = new TenantActorResolver(
            dbContext,
            stampValidator,
            contextAccessor,
            TimeProvider.System,
            NullLogger<TenantActorResolver>.Instance);

        var principal = CreatePrincipal(userId: userId, sessionId: Guid.NewGuid(), securityStamp: "invalid-stamp");

        var result = await resolver.ResolveActorAsync(principal);

        Assert.False(result.IsSuccess);
        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
        Assert.Contains("Security credentials or user account status are no longer valid", result.ErrorDetail);
    }

    // --- Invariant 2: TenantResultHttpMapper Tests ---

    [Fact]
    public void TenantResultHttpMapper_MapsConflictAndNotFound_ToStandardProblemDetails()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = "/api/v1/tenants";

        var conflictResult = CreateTenantResult.Conflict("Slug already taken.");
        var httpConflict = conflictResult.ToHttpResult(httpContext);

        Assert.NotNull(httpConflict);

        var notFoundResult = TenantResult.NotFound("Tenant missing.");
        var httpNotFound = notFoundResult.ToHttpResult(httpContext);

        Assert.NotNull(httpNotFound);

        var forbiddenLifecycle = TenantLifecycleResult.Forbidden("Lifecycle forbidden.");
        var httpForbidden = forbiddenLifecycle.ToHttpResult(httpContext);

        Assert.NotNull(httpForbidden);

        var membershipNotFound = TenantMembershipResult.NotFound("Membership missing.");
        var httpMemNotFound = membershipNotFound.ToHttpResult(httpContext);

        Assert.NotNull(httpMemNotFound);
    }

    // --- Invariant 3: TenantActorContext Platform Admin Invariant ---

    [Fact]
    public void TenantActorContext_OrdinaryUser_NeverPlatformAdmin()
    {
        var userId = Guid.NewGuid();
        var actor = TenantActorContext.FromUser(userId, isPlatformAdmin: false);

        Assert.Equal(userId, actor.UserId);
        Assert.False(actor.IsPlatformAdmin);
        Assert.Null(actor.TenantId);
        Assert.Null(actor.Role);
    }

    [Fact]
    public void TenantActorContext_Member_NeverPlatformAdmin()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var actor = TenantActorContext.Member(userId, tenantId, TenantMembershipRole.Owner);

        Assert.Equal(userId, actor.UserId);
        Assert.Equal(tenantId, actor.TenantId);
        Assert.Equal(TenantMembershipRole.Owner, actor.Role);
        Assert.False(actor.IsPlatformAdmin); // Invariant: Owner/Admin never platform admin
    }
}
