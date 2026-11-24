namespace MaintenX.UnitTests.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Models;
using Xunit;

/// <summary>
/// Unit tests for Tenant Application Contracts and Result Models.
/// Verifies initialization, property immutability, static factory behaviors,
/// status code conventions, and null-safety.
/// </summary>
public class TenantContractsAndModelsTests
{
    // =========================================================================
    // 1. DATA CONTRACTS TESTS
    // =========================================================================

    [Fact]
    public void CreateTenantRequest_InitializesPropertiesCorrectly()
    {
        var request = new CreateTenantRequest("acme-facilities", "Acme Facilities Management");

        Assert.Equal("acme-facilities", request.Slug);
        Assert.Equal("Acme Facilities Management", request.DisplayName);
    }

    [Fact]
    public void CreateTenantResponse_InitializesPropertiesCorrectly()
    {
        var tenantId = Guid.NewGuid();
        var now = DateTime.UtcNow;

        var response = new CreateTenantResponse(
            tenantId,
            "acme-facilities",
            "Acme Facilities Management",
            "Active",
            now);

        Assert.Equal(tenantId, response.TenantId);
        Assert.Equal("acme-facilities", response.Slug);
        Assert.Equal("Acme Facilities Management", response.DisplayName);
        Assert.Equal("Active", response.Status);
        Assert.Equal(now, response.CreatedAtUtc);
    }

    [Fact]
    public void UpdateTenantRequest_InitializesPropertiesCorrectly()
    {
        var request = new UpdateTenantRequest("New Display Name");
        Assert.Equal("New Display Name", request.DisplayName);
    }

    [Fact]
    public void TenantResponse_InitializesPropertiesCorrectly()
    {
        var id = Guid.NewGuid();
        var created = DateTime.UtcNow.AddDays(-1);
        var updated = DateTime.UtcNow;

        var response = new TenantResponse(
            id,
            "acme",
            "Acme Org",
            "Active",
            created,
            updated,
            5);

        Assert.Equal(id, response.Id);
        Assert.Equal("acme", response.Slug);
        Assert.Equal("Acme Org", response.DisplayName);
        Assert.Equal("Active", response.Status);
        Assert.Equal(created, response.CreatedAtUtc);
        Assert.Equal(updated, response.UpdatedAtUtc);
        Assert.Equal(5, response.Version);
    }

    [Fact]
    public void TenantLifecycleResponse_InitializesPropertiesCorrectly()
    {
        var tenantId = Guid.NewGuid();
        var now = DateTime.UtcNow;

        var response = new TenantLifecycleResponse(tenantId, "Suspended", now);

        Assert.Equal(tenantId, response.TenantId);
        Assert.Equal("Suspended", response.Status);
        Assert.Equal(now, response.UpdatedAtUtc);
    }

    [Fact]
    public void TenantMembershipResponse_InitializesPropertiesCorrectly()
    {
        var membershipId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var created = DateTime.UtcNow.AddHours(-2);
        var updated = DateTime.UtcNow;

        var response = new TenantMembershipResponse(
            membershipId,
            tenantId,
            userId,
            "Administrator",
            "Active",
            created,
            updated);

        Assert.Equal(membershipId, response.MembershipId);
        Assert.Equal(tenantId, response.TenantId);
        Assert.Equal(userId, response.UserId);
        Assert.Equal("Administrator", response.Role);
        Assert.Equal("Active", response.Status);
        Assert.Equal(created, response.CreatedAtUtc);
        Assert.Equal(updated, response.UpdatedAtUtc);
    }

    [Fact]
    public void UserTenantMembershipResponse_InitializesPropertiesCorrectly()
    {
        var membershipId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var created = DateTime.UtcNow;

        var response = new UserTenantMembershipResponse(
            membershipId,
            tenantId,
            "tenant-slug",
            "Tenant Display Name",
            "Owner",
            "Active",
            "Active",
            true,
            created);

        Assert.Equal(membershipId, response.MembershipId);
        Assert.Equal(tenantId, response.TenantId);
        Assert.Equal("tenant-slug", response.TenantSlug);
        Assert.Equal("Tenant Display Name", response.TenantDisplayName);
        Assert.Equal("Owner", response.Role);
        Assert.Equal("Active", response.Status);
        Assert.Equal("Active", response.TenantStatus);
        Assert.True(response.IsSelectable);
        Assert.Equal(created, response.CreatedAtUtc);
    }

    // =========================================================================
    // 2. CREATE TENANT RESULT TESTS
    // =========================================================================

    [Fact]
    public void CreateTenantResult_Success_Returns201WithResponse()
    {
        var response = new CreateTenantResponse(Guid.NewGuid(), "slug", "Name", "Active", DateTime.UtcNow);
        var result = CreateTenantResult.Success(response);

        Assert.True(result.IsSuccess);
        Assert.Equal(201, result.StatusCode);
        Assert.Equal(response, result.Response);
        Assert.Null(result.ErrorCode);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void CreateTenantResult_Success_NullResponse_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CreateTenantResult.Success(null!));
    }

    [Fact]
    public void CreateTenantResult_Conflict_Returns409WithErrorCode()
    {
        var result = CreateTenantResult.Conflict("Tenant slug 'acme' is already taken.");

        Assert.False(result.IsSuccess);
        Assert.Equal(409, result.StatusCode);
        Assert.Equal("TENANT_SLUG_CONFLICT", result.ErrorCode);
        Assert.Equal("Tenant slug 'acme' is already taken.", result.ErrorMessage);
        Assert.Null(result.Response);
    }

    [Fact]
    public void CreateTenantResult_ValidationFailed_Returns400()
    {
        var result = CreateTenantResult.ValidationFailed("Invalid slug length.");

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("VALIDATION_FAILED", result.ErrorCode);
        Assert.Equal("Invalid slug length.", result.ErrorMessage);
    }

    [Fact]
    public void CreateTenantResult_Unauthorized_Returns401()
    {
        var result = CreateTenantResult.Unauthorized();

        Assert.False(result.IsSuccess);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("UNAUTHORIZED", result.ErrorCode);
    }

    [Fact]
    public void CreateTenantResult_Forbidden_Returns403()
    {
        var result = CreateTenantResult.Forbidden();

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("FORBIDDEN", result.ErrorCode);
    }

    // =========================================================================
    // 3. TENANT RESULT TESTS
    // =========================================================================

    [Fact]
    public void TenantResult_Success_Returns200WithTenant()
    {
        var tenant = new TenantResponse(Guid.NewGuid(), "slug", "Name", "Active", DateTime.UtcNow, DateTime.UtcNow, 1);
        var result = TenantResult.Success(tenant);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.Equal(tenant, result.Tenant);
        Assert.Null(result.ErrorCode);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void TenantResult_NotFound_Returns404()
    {
        var result = TenantResult.NotFound();

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.Equal("TENANT_NOT_FOUND", result.ErrorCode);
    }

    [Fact]
    public void TenantResult_Forbidden_Returns403()
    {
        var result = TenantResult.Forbidden();

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("FORBIDDEN", result.ErrorCode);
    }

    [Fact]
    public void TenantResult_Conflict_Returns409()
    {
        var result = TenantResult.Conflict("Concurrency conflict.");

        Assert.False(result.IsSuccess);
        Assert.Equal(409, result.StatusCode);
        Assert.Equal("CONCURRENCY_CONFLICT", result.ErrorCode);
    }

    // =========================================================================
    // 4. TENANT LIFECYCLE RESULT TESTS
    // =========================================================================

    [Fact]
    public void TenantLifecycleResult_Success_Returns200()
    {
        var resp = new TenantLifecycleResponse(Guid.NewGuid(), "Active", DateTime.UtcNow);
        var result = TenantLifecycleResult.Success(resp);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.Equal(resp, result.Response);
    }

    [Fact]
    public void TenantLifecycleResult_InvalidState_Returns400()
    {
        var result = TenantLifecycleResult.InvalidState("Cannot suspend tenant in PendingOnboarding status.");

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_LIFECYCLE_TRANSITION", result.ErrorCode);
        Assert.Equal("Cannot suspend tenant in PendingOnboarding status.", result.ErrorMessage);
    }

    [Fact]
    public void TenantLifecycleResult_NotFound_Returns404()
    {
        var result = TenantLifecycleResult.NotFound();

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.Equal("TENANT_NOT_FOUND", result.ErrorCode);
    }

    // =========================================================================
    // 5. TENANT MEMBERSHIP RESULT TESTS
    // =========================================================================

    [Fact]
    public void TenantMembershipResult_Success_Returns200()
    {
        var membership = new TenantMembershipResponse(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "Member", "Active", DateTime.UtcNow, DateTime.UtcNow);
        var result = TenantMembershipResult.Success(membership);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.Equal(membership, result.Membership);
    }

    [Fact]
    public void TenantMembershipResult_NotFound_Returns404()
    {
        var result = TenantMembershipResult.NotFound();

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.Equal("MEMBERSHIP_NOT_FOUND", result.ErrorCode);
    }

    [Fact]
    public void TenantMembershipResult_Forbidden_Returns403()
    {
        var result = TenantMembershipResult.Forbidden();

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("FORBIDDEN", result.ErrorCode);
    }
}
