namespace MaintenX.UnitTests.Application.Authorization;

using System.Security.Claims;
using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Application.Authorization.Policies;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

public class PolicyAuthorizationHandlerTests
{
    private sealed class StubPlatformGrantResolver(PlatformGrantResolutionResult result) : IPlatformGrantResolver
    {
        public Task<PlatformGrantResolutionResult> ResolveAsync(PermissionKey? permission, CancellationToken cancellationToken = default) =>
            Task.FromResult(result);
    }

    private sealed class FakeTenantContextAccessor(ITenantContext? current) : ITenantContextAccessor
    {
        public ITenantContext? Current { get; set; } = current;
    }

    private sealed class StubTenantContext(Guid tenantId, Guid userId, TenantMembershipRole role) : ITenantContext
    {
        public Guid TenantId { get; } = tenantId;
        public string TenantSlug { get; } = "test-slug";
        public string TenantDisplayName { get; } = "Test Tenant";
        public Guid UserId { get; } = userId;
        public Guid MembershipId { get; } = Guid.NewGuid();
        public TenantMembershipRole Role { get; } = role;
        public TenantMembershipStatus Status { get; } = TenantMembershipStatus.Active;
        public DateTime ResolvedAtUtc { get; } = DateTime.UtcNow;
    }

    [Fact]
    public async Task PlatformPermissionHandler_AllowedByResolver_Succeeds()
    {
        var stubResolver = new StubPlatformGrantResolver(PlatformGrantResolutionResult.Allow(
            Guid.NewGuid(), Guid.NewGuid(), PlatformRole.PlatformAdministrator, PermissionCatalog.Platform.TenantsRead));

        var handler = new PlatformPermissionHandler(stubResolver, NullLogger<PlatformPermissionHandler>.Instance);
        var requirement = new PlatformPermissionRequirement(PermissionCatalog.Platform.TenantsRead);
        var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(), null);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task PlatformPermissionHandler_DeniedByResolver_FailsClosed()
    {
        var stubResolver = new StubPlatformGrantResolver(PlatformGrantResolutionResult.Deny("NoActivePlatformGrant"));

        var handler = new PlatformPermissionHandler(stubResolver, NullLogger<PlatformPermissionHandler>.Instance);
        var requirement = new PlatformPermissionRequirement(PermissionCatalog.Platform.TenantsRead);
        var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(), null);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task TenantPermissionHandler_OwnerWithSettingsUpdate_Succeeds()
    {
        var tenantContext = new StubTenantContext(Guid.NewGuid(), Guid.NewGuid(), TenantMembershipRole.Owner);
        var accessor = new FakeTenantContextAccessor(tenantContext);
        var handler = new TenantPermissionHandler(accessor, NullLogger<TenantPermissionHandler>.Instance);

        var requirement = new TenantPermissionRequirement(PermissionCatalog.Tenant.SettingsUpdate);
        var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(), null);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task TenantPermissionHandler_MemberWithSettingsUpdate_FailsClosed()
    {
        var tenantContext = new StubTenantContext(Guid.NewGuid(), Guid.NewGuid(), TenantMembershipRole.Member);
        var accessor = new FakeTenantContextAccessor(tenantContext);
        var handler = new TenantPermissionHandler(accessor, NullLogger<TenantPermissionHandler>.Instance);

        var requirement = new TenantPermissionRequirement(PermissionCatalog.Tenant.SettingsUpdate);
        var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(), null);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task TenantPermissionHandler_MissingTenantContext_FailsClosed()
    {
        var accessor = new FakeTenantContextAccessor(null);
        var handler = new TenantPermissionHandler(accessor, NullLogger<TenantPermissionHandler>.Instance);

        var requirement = new TenantPermissionRequirement(PermissionCatalog.Tenant.SettingsUpdate);
        var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(), null);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public void PlatformPermissionRequirement_RejectsTenantScopedPermission()
    {
        Assert.Throws<ArgumentException>(() =>
            new PlatformPermissionRequirement(PermissionCatalog.Tenant.MetadataRead));
    }

    [Fact]
    public void TenantPermissionRequirement_RejectsPlatformScopedPermission()
    {
        Assert.Throws<ArgumentException>(() =>
            new TenantPermissionRequirement(PermissionCatalog.Platform.TenantsRead));
    }

    [Fact]
    public void ConventionExtensions_ProduceExpectedPolicyNames()
    {
        Assert.Equal("Platform:platform.tenants.read",
            PermissionEndpointConventionBuilderExtensions.GetPlatformPolicyName(PermissionCatalog.Platform.TenantsRead));

        Assert.Equal("Tenant:tenant.settings.update",
            PermissionEndpointConventionBuilderExtensions.GetTenantPolicyName(PermissionCatalog.Tenant.SettingsUpdate));
    }
}
