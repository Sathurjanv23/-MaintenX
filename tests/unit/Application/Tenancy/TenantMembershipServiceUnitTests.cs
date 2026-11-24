namespace MaintenX.UnitTests.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Models;
using MaintenX.Api.Application.Tenancy.Services;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Unit tests for TenantMembershipService verifying input validation, unauthenticated actor guards,
/// cross-user discovery restrictions, and typed result contracts.
/// </summary>
public class TenantMembershipServiceUnitTests
{
    private static MaintenXDbContext CreateDummyContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=dummy;Username=dummy;Password=dummy")
            .Options;

        return new MaintenXDbContext(options);
    }

    [Fact]
    public async Task GetUserMembershipsAsync_EmptyUserId_ReturnsEmptyList()
    {
        var context = CreateDummyContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);

        var result = await service.GetUserMembershipsAsync(Guid.Empty);

        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetUserMembershipsAsync_UnauthenticatedActor_ReturnsEmptyList()
    {
        var context = CreateDummyContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var targetUserId = Guid.NewGuid();

        // Calling with null actor when no ambient context exists
        var result = await service.GetUserMembershipsAsync(targetUserId, actor: null);

        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetUserMembershipsAsync_ActorUserIdMismatch_ReturnsEmptyList()
    {
        var context = CreateDummyContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actorUserId = Guid.NewGuid();
        var targetUserId = Guid.NewGuid();
        var actor = TenantActorContext.FromUser(actorUserId);

        var result = await service.GetUserMembershipsAsync(targetUserId, actor);

        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetMembershipAsync_EmptyTenantId_ReturnsValidationFailed()
    {
        var context = CreateDummyContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);

        var result = await service.GetMembershipAsync(Guid.Empty, Guid.NewGuid());

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("VALIDATION_FAILED", result.ErrorCode);
    }

    [Fact]
    public async Task GetMembershipAsync_EmptyUserId_ReturnsValidationFailed()
    {
        var context = CreateDummyContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);

        var result = await service.GetMembershipAsync(Guid.NewGuid(), Guid.Empty);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("VALIDATION_FAILED", result.ErrorCode);
    }

    [Fact]
    public async Task GetMembershipAsync_UnauthenticatedActor_ReturnsNotFound()
    {
        var context = CreateDummyContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);

        var result = await service.GetMembershipAsync(Guid.NewGuid(), Guid.NewGuid(), actor: null);

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.Equal("MEMBERSHIP_NOT_FOUND", result.ErrorCode);
    }

    [Fact]
    public void TenantActorContext_FromUser_SetsPropertiesCorrectly()
    {
        var userId = Guid.NewGuid();
        var actor = TenantActorContext.FromUser(userId);

        Assert.Equal(userId, actor.UserId);
        Assert.False(actor.IsPlatformAdmin);
        Assert.Null(actor.TenantId);
        Assert.Null(actor.Role);
    }

    [Fact]
    public void TenantActorContext_PlatformAdmin_SetsFlagCorrectly()
    {
        var userId = Guid.NewGuid();
        var actor = TenantActorContext.PlatformAdmin(userId);

        Assert.Equal(userId, actor.UserId);
        Assert.True(actor.IsPlatformAdmin);
        Assert.Null(actor.TenantId);
        Assert.Null(actor.Role);
    }
}
