namespace MaintenX.UnitTests.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Models;
using MaintenX.Api.Application.Tenancy.Services;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Unit tests for TenantService verifying input validation, authorization guards,
/// error handling, lifecycle boundaries, and safe responses.
/// </summary>
public class TenantServiceUnitTests
{
    private static MaintenXDbContext CreateDummyContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=dummy;Username=dummy;Password=dummy")
            .Options;

        return new MaintenXDbContext(options);
    }

    [Fact]
    public async Task CreateTenantAsync_NullRequest_ReturnsValidationFailed()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.CreateTenantAsync(Guid.NewGuid(), null!);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("VALIDATION_FAILED", result.ErrorCode);
        Assert.Contains("null", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateTenantAsync_EmptyCreatorUserId_ReturnsUnauthorized()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var request = new CreateTenantRequest("acme", "Acme Corporation");

        var result = await service.CreateTenantAsync(Guid.Empty, request);

        Assert.False(result.IsSuccess);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("UNAUTHORIZED", result.ErrorCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("a")]
    [InlineData("acme--corp")]
    [InlineData("acme_corp")]
    [InlineData("acme corp")]
    public async Task CreateTenantAsync_InvalidSlug_ReturnsValidationFailed(string invalidSlug)
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var request = new CreateTenantRequest(invalidSlug, "Acme Corporation");

        var result = await service.CreateTenantAsync(Guid.NewGuid(), request);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("VALIDATION_FAILED", result.ErrorCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("A")]
    public async Task CreateTenantAsync_InvalidDisplayName_ReturnsValidationFailed(string invalidDisplayName)
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var request = new CreateTenantRequest("acme-corp", invalidDisplayName);

        var result = await service.CreateTenantAsync(Guid.NewGuid(), request);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("VALIDATION_FAILED", result.ErrorCode);
    }

    // --- Task 3.5.3 Unit Tests ---

    [Fact]
    public async Task GetTenantByIdAsync_EmptyTenantId_ReturnsValidationFailed()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.GetTenantByIdAsync(Guid.Empty);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_TENANT_ID", result.ErrorCode);
    }

    [Fact]
    public async Task GetTenantByIdAsync_UnauthenticatedCaller_ReturnsNotFound_AntiEnumeration()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        // Caller without actor and without TenantContextAccessor
        var result = await service.GetTenantByIdAsync(Guid.NewGuid(), actor: null);

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.Equal("TENANT_NOT_FOUND", result.ErrorCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("a")]
    [InlineData("acme--corp")]
    [InlineData("acme_corp")]
    [InlineData("acme corp")]
    public async Task GetTenantBySlugAsync_InvalidSlug_ReturnsValidationFailed(string invalidSlug)
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.GetTenantBySlugAsync(invalidSlug);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_SLUG", result.ErrorCode);
    }

    [Fact]
    public async Task GetTenantBySlugAsync_UnauthenticatedCaller_ReturnsNotFound_AntiEnumeration()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.GetTenantBySlugAsync("acme-facility", actor: null);

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.Equal("TENANT_NOT_FOUND", result.ErrorCode);
    }

    [Fact]
    public async Task UpdateTenantAsync_EmptyTenantId_ReturnsValidationFailed()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.UpdateTenantAsync(Guid.Empty, new UpdateTenantRequest("New Name"));

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_TENANT_ID", result.ErrorCode);
    }

    [Fact]
    public async Task UpdateTenantAsync_NullRequest_ReturnsValidationFailed()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.UpdateTenantAsync(Guid.NewGuid(), null!);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_REQUEST", result.ErrorCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("A")]
    public async Task UpdateTenantAsync_InvalidDisplayName_ReturnsValidationFailed(string invalidName)
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.UpdateTenantAsync(Guid.NewGuid(), new UpdateTenantRequest(invalidName));

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_DISPLAY_NAME", result.ErrorCode);
    }

    [Fact]
    public async Task UpdateTenantAsync_UnauthenticatedCaller_ReturnsForbidden()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.UpdateTenantAsync(Guid.NewGuid(), new UpdateTenantRequest("Valid Name"), actor: null);

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("FORBIDDEN", result.ErrorCode);
    }

    [Fact]
    public async Task ActivateTenantAsync_EmptyTenantId_ReturnsInvalidState()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.ActivateTenantAsync(Guid.Empty);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_TENANT_ID", result.ErrorCode);
    }

    [Fact]
    public async Task ActivateTenantAsync_NonPlatformAdmin_ReturnsForbidden()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var actor = TenantActorContext.FromUser(Guid.NewGuid(), isPlatformAdmin: false);

        var result = await service.ActivateTenantAsync(Guid.NewGuid(), actor);

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("FORBIDDEN", result.ErrorCode);
    }

    [Fact]
    public async Task SuspendTenantAsync_EmptyTenantId_ReturnsInvalidState()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.SuspendTenantAsync(Guid.Empty, "Valid administrative reason.");

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_TENANT_ID", result.ErrorCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("ab")]
    public async Task SuspendTenantAsync_InvalidReason_ReturnsInvalidState(string invalidReason)
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.SuspendTenantAsync(Guid.NewGuid(), invalidReason);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_REASON", result.ErrorCode);
    }

    [Fact]
    public async Task SuspendTenantAsync_NonPlatformAdmin_ReturnsForbidden()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var actor = TenantActorContext.Member(Guid.NewGuid(), Guid.NewGuid(), TenantMembershipRole.Owner);

        var result = await service.SuspendTenantAsync(Guid.NewGuid(), "Valid administrative justification.", actor);

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("FORBIDDEN", result.ErrorCode);
    }

    [Fact]
    public async Task DeactivateTenantAsync_EmptyTenantId_ReturnsInvalidState()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.DeactivateTenantAsync(Guid.Empty, "Valid administrative reason.");

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_TENANT_ID", result.ErrorCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("ab")]
    public async Task DeactivateTenantAsync_InvalidReason_ReturnsInvalidState(string invalidReason)
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.DeactivateTenantAsync(Guid.NewGuid(), invalidReason);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_REASON", result.ErrorCode);
    }

    [Fact]
    public async Task DeactivateTenantAsync_NonPlatformAdmin_ReturnsForbidden()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var actor = TenantActorContext.Member(Guid.NewGuid(), Guid.NewGuid(), TenantMembershipRole.Owner);

        var result = await service.DeactivateTenantAsync(Guid.NewGuid(), "Administrative contract termination.", actor);

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("FORBIDDEN", result.ErrorCode);
    }
}
