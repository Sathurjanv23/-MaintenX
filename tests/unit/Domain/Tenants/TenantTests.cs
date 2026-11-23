namespace MaintenX.UnitTests.Domain.Tenants;

using MaintenX.Api.Domain.Tenants;
using Xunit;

public class TenantTests
{
    [Fact]
    public void Create_WithValidParameters_InitializesTenantCorrectly()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation");

        Assert.NotEqual(Guid.Empty, tenant.Id);
        Assert.Equal("acme-corp", tenant.Slug);
        Assert.Equal("Acme Corporation", tenant.DisplayName);
        Assert.Equal(TenantStatus.PendingOnboarding, tenant.Status);
        Assert.False(tenant.IsActive);
        Assert.True(tenant.CanAcceptMembers);
        Assert.Equal(1, tenant.Version);
    }

    [Fact]
    public void Create_WithExplicitActiveStatus_SetsStatusToActive()
    {
        var tenant = Tenant.Create("beta-hospital", "Beta Hospital", TenantStatus.Active);

        Assert.Equal(TenantStatus.Active, tenant.Status);
        Assert.True(tenant.IsActive);
        Assert.True(tenant.CanAcceptMembers);
    }

    [Theory]
    [InlineData("acme-corp")]
    [InlineData("campus-1")]
    [InlineData("a1-b2-c3")]
    [InlineData("hospital")]
    public void NormalizeAndValidateSlug_WithValidSlugs_ReturnsNormalized(string slug)
    {
        var normalized = Tenant.NormalizeAndValidateSlug(slug);
        Assert.Equal(slug.ToLowerInvariant(), normalized);
    }

    [Theory]
    [InlineData(" acme-corp")]
    [InlineData("acme-corp ")]
    [InlineData("  ")]
    public void NormalizeAndValidateSlug_WithWhitespace_ThrowsArgumentException(string slug)
    {
        Assert.Throws<ArgumentException>(() => Tenant.NormalizeAndValidateSlug(slug));
    }

    [Theory]
    [InlineData("a")]
    [InlineData("acme--corp")]
    [InlineData("-acme")]
    [InlineData("acme-")]
    [InlineData("acme_corp")]
    [InlineData("acme.corp")]
    [InlineData("acme@corp")]
    public void NormalizeAndValidateSlug_WithInvalidPattern_ThrowsArgumentException(string slug)
    {
        Assert.Throws<ArgumentException>(() => Tenant.NormalizeAndValidateSlug(slug));
    }

    [Fact]
    public void Activate_FromPendingOnboarding_TransitionsToActive()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation", TenantStatus.PendingOnboarding);
        var activateTime = DateTime.UtcNow.AddMinutes(5);

        tenant.Activate(activateTime);

        Assert.Equal(TenantStatus.Active, tenant.Status);
        Assert.True(tenant.IsActive);
        Assert.Equal(activateTime, tenant.UpdatedAtUtc);
        Assert.Equal(2, tenant.Version);
    }

    [Fact]
    public void Activate_FromSuspended_TransitionsToActive()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation", TenantStatus.Active);
        tenant.Suspend(DateTime.UtcNow.AddMinutes(2));

        var activateTime = DateTime.UtcNow.AddMinutes(5);
        tenant.Activate(activateTime);

        Assert.Equal(TenantStatus.Active, tenant.Status);
        Assert.True(tenant.IsActive);
        Assert.Equal(activateTime, tenant.UpdatedAtUtc);
        Assert.Equal(3, tenant.Version);
    }

    [Fact]
    public void Activate_WhenAlreadyActive_IsIdempotent()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation", TenantStatus.Active);
        var originalUpdatedAt = tenant.UpdatedAtUtc;
        var originalVersion = tenant.Version;

        tenant.Activate(DateTime.UtcNow.AddMinutes(5));

        Assert.Equal(TenantStatus.Active, tenant.Status);
        Assert.Equal(originalUpdatedAt, tenant.UpdatedAtUtc);
        Assert.Equal(originalVersion, tenant.Version);
    }

    [Fact]
    public void Activate_WhenDeactivated_ThrowsInvalidOperationException()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation");
        tenant.Deactivate(DateTime.UtcNow);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            tenant.Activate(DateTime.UtcNow));

        Assert.Contains("deactivated", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Suspend_WhenActive_TransitionsToSuspended()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation", TenantStatus.Active);
        var suspendTime = DateTime.UtcNow.AddMinutes(5);

        tenant.Suspend(suspendTime);

        Assert.Equal(TenantStatus.Suspended, tenant.Status);
        Assert.False(tenant.IsActive);
        Assert.False(tenant.CanAcceptMembers);
        Assert.Equal(suspendTime, tenant.UpdatedAtUtc);
        Assert.Equal(2, tenant.Version);
    }

    [Fact]
    public void Suspend_WhenAlreadySuspended_IsIdempotent()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation", TenantStatus.Active);
        tenant.Suspend(DateTime.UtcNow.AddMinutes(2));

        var originalUpdatedAt = tenant.UpdatedAtUtc;
        var originalVersion = tenant.Version;

        tenant.Suspend(DateTime.UtcNow.AddMinutes(5));

        Assert.Equal(TenantStatus.Suspended, tenant.Status);
        Assert.Equal(originalUpdatedAt, tenant.UpdatedAtUtc);
        Assert.Equal(originalVersion, tenant.Version);
    }

    [Fact]
    public void Suspend_WhenPendingOnboarding_ThrowsInvalidOperationException()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation", TenantStatus.PendingOnboarding);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            tenant.Suspend(DateTime.UtcNow));

        Assert.Contains("PendingOnboarding", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Suspend_WhenDeactivated_ThrowsInvalidOperationException()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation");
        tenant.Deactivate(DateTime.UtcNow);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            tenant.Suspend(DateTime.UtcNow));

        Assert.Contains("deactivated", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Deactivate_FromAnyState_TransitionsToDeactivated()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation", TenantStatus.Active);
        var deactivateTime = DateTime.UtcNow.AddMinutes(5);

        tenant.Deactivate(deactivateTime);

        Assert.Equal(TenantStatus.Deactivated, tenant.Status);
        Assert.False(tenant.IsActive);
        Assert.False(tenant.CanAcceptMembers);
        Assert.Equal(deactivateTime, tenant.UpdatedAtUtc);
        Assert.Equal(2, tenant.Version);
    }

    [Fact]
    public void Deactivate_WhenAlreadyDeactivated_IsIdempotent()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corporation");
        tenant.Deactivate(DateTime.UtcNow.AddMinutes(2));

        var originalUpdatedAt = tenant.UpdatedAtUtc;
        var originalVersion = tenant.Version;

        tenant.Deactivate(DateTime.UtcNow.AddMinutes(5));

        Assert.Equal(TenantStatus.Deactivated, tenant.Status);
        Assert.Equal(originalUpdatedAt, tenant.UpdatedAtUtc);
        Assert.Equal(originalVersion, tenant.Version);
    }

    [Fact]
    public void UpdateDisplayName_WithValidName_UpdatesAndIncrementsVersion()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corp");
        var updateTime = DateTime.UtcNow.AddMinutes(5);

        tenant.UpdateDisplayName("Acme Global Facility Services", updateTime);

        Assert.Equal("Acme Global Facility Services", tenant.DisplayName);
        Assert.Equal(updateTime, tenant.UpdatedAtUtc);
        Assert.Equal(2, tenant.Version);
    }

    [Fact]
    public void UpdateDisplayName_WhenSameName_IsIdempotent()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corp");
        var originalUpdatedAt = tenant.UpdatedAtUtc;
        var originalVersion = tenant.Version;

        tenant.UpdateDisplayName("  Acme Corp  ", DateTime.UtcNow.AddMinutes(5));

        Assert.Equal("Acme Corp", tenant.DisplayName);
        Assert.Equal(originalUpdatedAt, tenant.UpdatedAtUtc);
        Assert.Equal(originalVersion, tenant.Version);
    }

    [Fact]
    public void UpdateDisplayName_WhenDeactivated_ThrowsInvalidOperationException()
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corp");
        tenant.Deactivate(DateTime.UtcNow);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            tenant.UpdateDisplayName("New Name", DateTime.UtcNow));

        Assert.Contains("deactivated", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void UpdateDisplayName_WithEmptyName_ThrowsArgumentException(string name)
    {
        var tenant = Tenant.Create("acme-corp", "Acme Corp");

        Assert.Throws<ArgumentException>(() =>
            tenant.UpdateDisplayName(name, DateTime.UtcNow));
    }
}
