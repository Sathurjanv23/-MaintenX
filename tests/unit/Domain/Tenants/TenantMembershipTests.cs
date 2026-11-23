namespace MaintenX.UnitTests.Domain.Tenants;

using MaintenX.Api.Domain.Tenants;
using Xunit;

public class TenantMembershipTests
{
    private static readonly Guid ValidTenantId = Guid.NewGuid();
    private static readonly Guid ValidUserId = Guid.NewGuid();

    [Fact]
    public void Create_WithValidParameters_InitializesMembershipCorrectly()
    {
        var now = DateTime.UtcNow;
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Owner,
            TenantMembershipStatus.Active,
            now);

        Assert.NotEqual(Guid.Empty, membership.Id);
        Assert.Equal(ValidTenantId, membership.TenantId);
        Assert.Equal(ValidUserId, membership.UserId);
        Assert.Equal(TenantMembershipRole.Owner, membership.Role);
        Assert.Equal(TenantMembershipStatus.Active, membership.Status);
        Assert.True(membership.IsActive);
        Assert.Equal(now, membership.CreatedAtUtc);
        Assert.Equal(now, membership.UpdatedAtUtc);
        Assert.Null(membership.DeactivatedAtUtc);
        Assert.Equal(1, membership.Version);
    }

    [Fact]
    public void Create_ImplementsITenantEntity()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member);

        Assert.IsAssignableFrom<ITenantEntity>(membership);
        Assert.Equal(ValidTenantId, ((ITenantEntity)membership).TenantId);
    }

    [Fact]
    public void Create_WithEmptyTenantId_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            TenantMembership.Create(Guid.Empty, ValidUserId, TenantMembershipRole.Member));

        Assert.Contains("TenantId", ex.Message);
    }

    [Fact]
    public void Create_WithEmptyUserId_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            TenantMembership.Create(ValidTenantId, Guid.Empty, TenantMembershipRole.Member));

        Assert.Contains("UserId", ex.Message);
    }

    [Fact]
    public void Create_WithInvalidRole_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            TenantMembership.Create(ValidTenantId, ValidUserId, (TenantMembershipRole)999));

        Assert.Contains("TenantMembershipRole", ex.Message);
    }

    [Fact]
    public void Create_WithInvalidStatus_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            TenantMembership.Create(ValidTenantId, ValidUserId, TenantMembershipRole.Member, (TenantMembershipStatus)999));

        Assert.Contains("TenantMembershipStatus", ex.Message);
    }

    [Fact]
    public void Create_WithRevokedStatus_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            TenantMembership.Create(ValidTenantId, ValidUserId, TenantMembershipRole.Member, TenantMembershipStatus.Revoked));

        Assert.Contains("Revoked", ex.Message);
    }

    [Fact]
    public void Create_WithSuspendedStatus_SetsDeactivatedAtUtc()
    {
        var now = DateTime.UtcNow;
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Suspended,
            now);

        Assert.Equal(TenantMembershipStatus.Suspended, membership.Status);
        Assert.False(membership.IsActive);
        Assert.Equal(now, membership.DeactivatedAtUtc);
    }

    [Fact]
    public void Create_WithPendingStatus_IsNotActiveAndDeactivatedIsNull()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Pending);

        Assert.Equal(TenantMembershipStatus.Pending, membership.Status);
        Assert.False(membership.IsActive);
        Assert.Null(membership.DeactivatedAtUtc);
    }

    [Fact]
    public void Activate_FromPending_TransitionsToActiveAndIncrementsVersion()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Pending);

        var activateTime = DateTime.UtcNow.AddMinutes(5);
        membership.Activate(activateTime);

        Assert.Equal(TenantMembershipStatus.Active, membership.Status);
        Assert.True(membership.IsActive);
        Assert.Null(membership.DeactivatedAtUtc);
        Assert.Equal(activateTime, membership.UpdatedAtUtc);
        Assert.Equal(2, membership.Version);
    }

    [Fact]
    public void Activate_FromSuspended_TransitionsToActiveAndClearsDeactivatedAt()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Suspended);

        Assert.NotNull(membership.DeactivatedAtUtc);

        var activateTime = DateTime.UtcNow.AddMinutes(10);
        membership.Activate(activateTime);

        Assert.Equal(TenantMembershipStatus.Active, membership.Status);
        Assert.True(membership.IsActive);
        Assert.Null(membership.DeactivatedAtUtc);
        Assert.Equal(activateTime, membership.UpdatedAtUtc);
        Assert.Equal(2, membership.Version);
    }

    [Fact]
    public void Activate_WhenAlreadyActive_IsIdempotent()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active);

        var originalUpdatedAt = membership.UpdatedAtUtc;
        var originalVersion = membership.Version;

        membership.Activate(DateTime.UtcNow.AddMinutes(5));

        Assert.Equal(TenantMembershipStatus.Active, membership.Status);
        Assert.Equal(originalUpdatedAt, membership.UpdatedAtUtc);
        Assert.Equal(originalVersion, membership.Version);
    }

    [Fact]
    public void Activate_WhenRevoked_ThrowsInvalidOperationException()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member);

        membership.Revoke(DateTime.UtcNow);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            membership.Activate(DateTime.UtcNow));

        Assert.Contains("revoked", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Suspend_WhenActive_TransitionsToSuspendedAndSetsDeactivatedAt()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active);

        var suspendTime = DateTime.UtcNow.AddMinutes(5);
        membership.Suspend(suspendTime);

        Assert.Equal(TenantMembershipStatus.Suspended, membership.Status);
        Assert.False(membership.IsActive);
        Assert.Equal(suspendTime, membership.DeactivatedAtUtc);
        Assert.Equal(suspendTime, membership.UpdatedAtUtc);
        Assert.Equal(2, membership.Version);
    }

    [Fact]
    public void Suspend_WhenAlreadySuspended_IsIdempotent()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Suspended);

        var originalUpdatedAt = membership.UpdatedAtUtc;
        var originalDeactivatedAt = membership.DeactivatedAtUtc;
        var originalVersion = membership.Version;

        membership.Suspend(DateTime.UtcNow.AddMinutes(5));

        Assert.Equal(TenantMembershipStatus.Suspended, membership.Status);
        Assert.Equal(originalUpdatedAt, membership.UpdatedAtUtc);
        Assert.Equal(originalDeactivatedAt, membership.DeactivatedAtUtc);
        Assert.Equal(originalVersion, membership.Version);
    }

    [Fact]
    public void Suspend_WhenPending_ThrowsInvalidOperationException()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Pending);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            membership.Suspend(DateTime.UtcNow));

        Assert.Contains("pending", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Suspend_WhenRevoked_ThrowsInvalidOperationException()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member);

        membership.Revoke(DateTime.UtcNow);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            membership.Suspend(DateTime.UtcNow));

        Assert.Contains("revoked", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Revoke_FromActive_TransitionsToRevoked()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active);

        var revokeTime = DateTime.UtcNow.AddMinutes(5);
        membership.Revoke(revokeTime);

        Assert.Equal(TenantMembershipStatus.Revoked, membership.Status);
        Assert.False(membership.IsActive);
        Assert.Equal(revokeTime, membership.DeactivatedAtUtc);
        Assert.Equal(revokeTime, membership.UpdatedAtUtc);
        Assert.Equal(2, membership.Version);
    }

    [Fact]
    public void Revoke_WhenAlreadyRevoked_IsIdempotent()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member);

        var revokeTime = DateTime.UtcNow.AddMinutes(5);
        membership.Revoke(revokeTime);

        var originalUpdatedAt = membership.UpdatedAtUtc;
        var originalVersion = membership.Version;

        membership.Revoke(DateTime.UtcNow.AddMinutes(10));

        Assert.Equal(TenantMembershipStatus.Revoked, membership.Status);
        Assert.Equal(originalUpdatedAt, membership.UpdatedAtUtc);
        Assert.Equal(originalVersion, membership.Version);
    }

    [Fact]
    public void ChangeRole_WithValidNewRole_UpdatesRoleAndVersion()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member);

        var updateTime = DateTime.UtcNow.AddMinutes(5);
        membership.ChangeRole(TenantMembershipRole.Administrator, updateTime);

        Assert.Equal(TenantMembershipRole.Administrator, membership.Role);
        Assert.Equal(updateTime, membership.UpdatedAtUtc);
        Assert.Equal(2, membership.Version);
    }

    [Fact]
    public void ChangeRole_WhenSameRole_IsIdempotent()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member);

        var originalUpdatedAt = membership.UpdatedAtUtc;
        var originalVersion = membership.Version;

        membership.ChangeRole(TenantMembershipRole.Member, DateTime.UtcNow.AddMinutes(5));

        Assert.Equal(TenantMembershipRole.Member, membership.Role);
        Assert.Equal(originalUpdatedAt, membership.UpdatedAtUtc);
        Assert.Equal(originalVersion, membership.Version);
    }

    [Fact]
    public void ChangeRole_WhenRevoked_ThrowsInvalidOperationException()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member);

        membership.Revoke(DateTime.UtcNow);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            membership.ChangeRole(TenantMembershipRole.Owner, DateTime.UtcNow));

        Assert.Contains("revoked", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ChangeRole_WithInvalidRole_ThrowsArgumentException()
    {
        var membership = TenantMembership.Create(
            ValidTenantId,
            ValidUserId,
            TenantMembershipRole.Member);

        Assert.Throws<ArgumentException>(() =>
            membership.ChangeRole((TenantMembershipRole)999, DateTime.UtcNow));
    }
}
