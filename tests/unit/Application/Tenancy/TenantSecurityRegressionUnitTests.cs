namespace MaintenX.UnitTests.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Models;
using MaintenX.Api.Application.Tenancy.Services;
using MaintenX.Api.Application.Tenancy.Validation;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Unit test suite for FEAT-003 Task 3.5.5 Security Regression.
/// Validates actor boundary invariants, anti-forgery defenses, injection attack resistance in validation,
/// and optimistic concurrency token constraints.
/// </summary>
public class TenantSecurityRegressionUnitTests
{
    private static MaintenXDbContext CreateDummyContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=dummy;Username=dummy;Password=dummy")
            .Options;

        return new MaintenXDbContext(options);
    }

    // --- Invariant 1: Anti-Injection in TenantValidation ---

    [Theory]
    [InlineData("acme' OR '1'='1")]
    [InlineData("acme; DROP TABLE tenants;--")]
    [InlineData("acme<script>alert(1)</script>")]
    [InlineData("../../../etc/passwd")]
    [InlineData("acme/tenant")]
    [InlineData("acme\\tenant")]
    [InlineData("acme\0null")]
    [InlineData("a")]
    [InlineData("-acme")]
    [InlineData("acme-")]
    [InlineData("acme--corp")]
    public void TenantValidation_MaliciousSlugs_AreRejected(string maliciousSlug)
    {
        Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndNormalizeSlug(maliciousSlug));
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("   ")]
    [InlineData("a")]
    public void TenantValidation_DisplayName_LengthBoundariesEnforced(string invalidDisplayName)
    {
        Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndTrimDisplayName(invalidDisplayName));
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("no")]
    public void TenantValidation_Reason_LengthBoundariesEnforced(string invalidReason)
    {
        Assert.Throws<ArgumentException>(() => TenantValidation.ValidateReason(invalidReason));
    }

    // --- Invariant 2: Actor Context Safety & Null Handling ---

    [Fact]
    public void TenantActorContext_FromTenantContext_NullContextReturnsNull()
    {
        var actor = TenantActorContext.FromTenantContext(null);
        Assert.Null(actor);
    }

    [Fact]
    public async Task TenantService_UnauthenticatedCaller_RejectsAllOperationsFailClosed()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var tenantId = Guid.NewGuid();

        // 1. GetTenantById with unauthenticated actor
        var getByIdResult = await service.GetTenantByIdAsync(tenantId, actor: null);
        Assert.False(getByIdResult.IsSuccess);
        Assert.Equal(404, getByIdResult.StatusCode);

        // 2. GetTenantBySlug with unauthenticated actor
        var getBySlugResult = await service.GetTenantBySlugAsync("acme", actor: null);
        Assert.False(getBySlugResult.IsSuccess);
        Assert.Equal(404, getBySlugResult.StatusCode);

        // 3. UpdateTenant with unauthenticated actor
        var updateResult = await service.UpdateTenantAsync(tenantId, new UpdateTenantRequest("New Name"), actor: null);
        Assert.False(updateResult.IsSuccess);
        Assert.Equal(403, updateResult.StatusCode);

        // 4. ActivateTenant with unauthenticated actor
        var actResult = await service.ActivateTenantAsync(tenantId, actor: null);
        Assert.False(actResult.IsSuccess);
        Assert.Equal(403, actResult.StatusCode);

        // 5. SuspendTenant with unauthenticated actor
        var suspResult = await service.SuspendTenantAsync(tenantId, "Reason for hold", actor: null);
        Assert.False(suspResult.IsSuccess);
        Assert.Equal(403, suspResult.StatusCode);

        // 6. DeactivateTenant with unauthenticated actor
        var deactResult = await service.DeactivateTenantAsync(tenantId, "Reason for termination", actor: null);
        Assert.False(deactResult.IsSuccess);
        Assert.Equal(403, deactResult.StatusCode);
    }

    [Fact]
    public async Task TenantMembershipService_UnauthenticatedCaller_RejectsAllOperationsFailClosed()
    {
        var context = CreateDummyContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var targetUserId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        // 1. GetUserMemberships with unauthenticated actor
        var userMemberships = await service.GetUserMembershipsAsync(targetUserId, actor: null);
        Assert.Empty(userMemberships);

        // 2. GetMembership with unauthenticated actor
        var membershipResult = await service.GetMembershipAsync(tenantId, targetUserId, actor: null);
        Assert.False(membershipResult.IsSuccess);
        Assert.Equal(404, membershipResult.StatusCode);
    }

    [Fact]
    public void UpdateTenantRequest_ExpectedVersion_PreservedCorrectly()
    {
        var reqWithoutVersion = new UpdateTenantRequest("Acme New Name");
        Assert.Null(reqWithoutVersion.ExpectedVersion);

        var reqWithVersion = new UpdateTenantRequest("Acme New Name", ExpectedVersion: 42);
        Assert.Equal(42, reqWithVersion.ExpectedVersion);
    }
}
