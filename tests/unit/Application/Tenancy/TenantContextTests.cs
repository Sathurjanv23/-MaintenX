namespace MaintenX.UnitTests.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Application.Tenancy.Resolution;
using MaintenX.Api.Domain.Tenants;
using Xunit;

public class TenantContextTests
{
    private static readonly Guid ValidTenantId = Guid.NewGuid();
    private static readonly Guid ValidUserId = Guid.NewGuid();
    private static readonly Guid ValidMembershipId = Guid.NewGuid();

    [Fact]
    public void TenantContext_Create_WithValidParameters_InitializesCorrectly()
    {
        var now = DateTime.UtcNow;
        var context = new TenantContext(
            ValidTenantId,
            "acme-corp",
            "Acme Corporation",
            ValidUserId,
            ValidMembershipId,
            TenantMembershipRole.Owner,
            TenantMembershipStatus.Active,
            now);

        Assert.Equal(ValidTenantId, context.TenantId);
        Assert.Equal("acme-corp", context.TenantSlug);
        Assert.Equal("Acme Corporation", context.TenantDisplayName);
        Assert.Equal(ValidUserId, context.UserId);
        Assert.Equal(ValidMembershipId, context.MembershipId);
        Assert.Equal(TenantMembershipRole.Owner, context.Role);
        Assert.Equal(TenantMembershipStatus.Active, context.Status);
        Assert.Equal(now, context.ResolvedAtUtc);
    }

    [Fact]
    public void TenantContext_Create_WithEmptyTenantId_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new TenantContext(
            Guid.Empty,
            "acme-corp",
            "Acme Corp",
            ValidUserId,
            ValidMembershipId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active,
            DateTime.UtcNow));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void TenantContext_Create_WithEmptyTenantSlug_ThrowsArgumentException(string slug)
    {
        Assert.Throws<ArgumentException>(() => new TenantContext(
            ValidTenantId,
            slug,
            "Acme Corp",
            ValidUserId,
            ValidMembershipId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active,
            DateTime.UtcNow));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void TenantContext_Create_WithEmptyDisplayName_ThrowsArgumentException(string name)
    {
        Assert.Throws<ArgumentException>(() => new TenantContext(
            ValidTenantId,
            "acme-corp",
            name,
            ValidUserId,
            ValidMembershipId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active,
            DateTime.UtcNow));
    }

    [Fact]
    public void TenantContext_Create_WithEmptyUserId_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new TenantContext(
            ValidTenantId,
            "acme-corp",
            "Acme Corp",
            Guid.Empty,
            ValidMembershipId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active,
            DateTime.UtcNow));
    }

    [Fact]
    public void TenantContext_Create_WithEmptyMembershipId_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new TenantContext(
            ValidTenantId,
            "acme-corp",
            "Acme Corp",
            ValidUserId,
            Guid.Empty,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active,
            DateTime.UtcNow));
    }

    [Fact]
    public void TenantContextAccessor_InitialState_CurrentIsNull_HasContextIsFalse()
    {
        var accessor = new TenantContextAccessor();

        Assert.Null(accessor.Current);
        Assert.False(accessor.HasContext);
    }

    [Fact]
    public void TenantContextAccessor_SetContext_SetsCurrent_HasContextIsTrue()
    {
        var accessor = new TenantContextAccessor();
        var context = new TenantContext(
            ValidTenantId,
            "acme-corp",
            "Acme Corp",
            ValidUserId,
            ValidMembershipId,
            TenantMembershipRole.Administrator,
            TenantMembershipStatus.Active,
            DateTime.UtcNow);

        accessor.SetContext(context);

        Assert.NotNull(accessor.Current);
        Assert.True(accessor.HasContext);
        Assert.Same(context, accessor.Current);
    }

    [Fact]
    public void TenantContextAccessor_SetContext_WhenAlreadySet_ThrowsInvalidOperationException()
    {
        var accessor = new TenantContextAccessor();
        var context1 = new TenantContext(
            ValidTenantId,
            "acme-corp",
            "Acme Corp",
            ValidUserId,
            ValidMembershipId,
            TenantMembershipRole.Administrator,
            TenantMembershipStatus.Active,
            DateTime.UtcNow);

        var context2 = new TenantContext(
            Guid.NewGuid(),
            "other-corp",
            "Other Corp",
            ValidUserId,
            Guid.NewGuid(),
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active,
            DateTime.UtcNow);

        accessor.SetContext(context1);

        var ex = Assert.Throws<InvalidOperationException>(() => accessor.SetContext(context2));
        Assert.Contains("already been initialized", ex.Message);
        Assert.Same(context1, accessor.Current);
    }

    [Fact]
    public void TenantResolutionResult_Success_ReturnsValidState()
    {
        var context = new TenantContext(
            ValidTenantId,
            "acme-corp",
            "Acme Corp",
            ValidUserId,
            ValidMembershipId,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active,
            DateTime.UtcNow);

        var result = TenantResolutionResult.Success(context);

        Assert.True(result.IsSuccess);
        Assert.Same(context, result.Context);
        Assert.Equal(200, result.StatusCode);
        Assert.Null(result.ErrorTitle);
        Assert.Null(result.ErrorDetail);
    }

    [Fact]
    public void TenantResolutionResult_Failure_ReturnsExplicitErrorDetails()
    {
        var result = TenantResolutionResult.Failure(403, "Forbidden", "Access denied.");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Context);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("Forbidden", result.ErrorTitle);
        Assert.Equal("Access denied.", result.ErrorDetail);
    }
}
