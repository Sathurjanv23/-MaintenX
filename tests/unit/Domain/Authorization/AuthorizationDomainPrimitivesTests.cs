namespace MaintenX.UnitTests.Domain.Authorization;

using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using Xunit;

public class AuthorizationDomainPrimitivesTests
{
    // =========================================================================
    // 1. AUTHORIZATION SCOPE TESTS
    // =========================================================================

    [Fact]
    public void PlatformScope_IsValidAndHasNoTenantId()
    {
        var scope = AuthorizationScope.Platform;

        Assert.Equal(AuthorizationScopeKind.Platform, scope.Kind);
        Assert.True(scope.IsPlatform);
        Assert.False(scope.IsTenant);
        Assert.Null(scope.TenantId);
        Assert.Equal("platform", scope.ToString());
        Assert.Same(AuthorizationScope.Platform, AuthorizationScope.Create(AuthorizationScopeKind.Platform));
    }

    [Fact]
    public void TenantScope_ForValidTenantId_IsValidAndBoundToExactTenant()
    {
        var tenantId = Guid.NewGuid();
        var scope = AuthorizationScope.ForTenant(tenantId);

        Assert.Equal(AuthorizationScopeKind.Tenant, scope.Kind);
        Assert.False(scope.IsPlatform);
        Assert.True(scope.IsTenant);
        Assert.Equal(tenantId, scope.TenantId);
        Assert.Equal($"tenant:{tenantId}", scope.ToString());
        Assert.Equal(scope, AuthorizationScope.Create(AuthorizationScopeKind.Tenant, tenantId));
    }

    [Fact]
    public void AuthorizationScope_InvalidScopeKind_ThrowsArgumentException()
    {
        var invalidKind = (AuthorizationScopeKind)999;
        Assert.Throws<ArgumentException>(() => AuthorizationScope.Create(invalidKind));
    }

    [Fact]
    public void TenantScope_EmptyOrMissingTenantId_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => AuthorizationScope.ForTenant(Guid.Empty));
        Assert.Throws<ArgumentException>(() => AuthorizationScope.Create(AuthorizationScopeKind.Tenant, null));
        Assert.Throws<ArgumentException>(() => AuthorizationScope.Create(AuthorizationScopeKind.Tenant, Guid.Empty));
    }

    [Fact]
    public void PlatformScope_WithTenantId_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            AuthorizationScope.Create(AuthorizationScopeKind.Platform, Guid.NewGuid()));
    }

    [Fact]
    public void AuthorizationScope_EqualityAndIsolation_PlatformCannotEqualTenant()
    {
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();

        var scopeA1 = AuthorizationScope.ForTenant(tenantA);
        var scopeA2 = AuthorizationScope.ForTenant(tenantA);
        var scopeB = AuthorizationScope.ForTenant(tenantB);

        Assert.Equal(scopeA1, scopeA2);
        Assert.Equal(scopeA1.GetHashCode(), scopeA2.GetHashCode());
        Assert.True(scopeA1 == scopeA2);
        Assert.NotEqual(scopeA1, scopeB);
        Assert.NotEqual(AuthorizationScope.Platform, scopeA1);
        Assert.True(AuthorizationScope.Platform != scopeA1);
    }

    // =========================================================================
    // 2. PERMISSION KEY TESTS
    // =========================================================================

    [Theory]
    [InlineData("platform.tenants.approve", AuthorizationScopeKind.Platform)]
    [InlineData("platform.tenants.read", AuthorizationScopeKind.Platform)]
    [InlineData("tenant.settings.update", AuthorizationScopeKind.Tenant)]
    [InlineData("tenant.members.roles.assign", AuthorizationScopeKind.Tenant)]
    [InlineData("tenant.audit_logs.read", AuthorizationScopeKind.Tenant)]
    public void PermissionKey_ValidIdentifiers_ParseWithExpectedScope(string raw, AuthorizationScopeKind expectedScope)
    {
        var key = PermissionKey.Parse(raw);

        Assert.Equal(raw, key.Value);
        Assert.Equal(expectedScope, key.Scope);
        Assert.Equal(raw, key.ToString());
        Assert.True(PermissionKey.TryParse(raw, out var tryParsed));
        Assert.Equal(key, tryParsed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(" tenant.settings.update")]
    [InlineData("tenant.settings.update ")]
    public void PermissionKey_NullEmptyOrWhitespace_Rejected(string? invalid)
    {
        Assert.Throws<ArgumentException>(() => PermissionKey.Parse(invalid));
        Assert.False(PermissionKey.TryParse(invalid, out var parsed));
        Assert.Null(parsed);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("tenant.*")]
    [InlineData("platform.tenants.*")]
    [InlineData("tenant.*.update")]
    public void PermissionKey_Wildcards_Rejected(string wildcard)
    {
        Assert.Throws<ArgumentException>(() => PermissionKey.Parse(wildcard));
        Assert.False(PermissionKey.TryParse(wildcard, out _));
    }

    [Theory]
    [InlineData("Tenant.settings.update")]
    [InlineData("platform")]
    [InlineData("tenant.")]
    [InlineData("global.tenants.read")]
    [InlineData("admin.tenants.approve")]
    [InlineData("tenant..update")]
    [InlineData("tenant.settings.update!")]
    [InlineData("tenant/settings/update")]
    [InlineData("tenant.a.b.c.d.e")]
    public void PermissionKey_MalformedOrAmbiguousPrefix_Rejected(string malformed)
    {
        Assert.Throws<ArgumentException>(() => PermissionKey.Parse(malformed));
        Assert.False(PermissionKey.TryParse(malformed, out _));
    }

    [Fact]
    public void PermissionKey_ExcessivelyLongIdentifier_Rejected()
    {
        var oversized = "tenant." + new string('a', PermissionKey.MaxLength);
        Assert.Throws<ArgumentException>(() => PermissionKey.Parse(oversized));
        Assert.False(PermissionKey.TryParse(oversized, out _));
    }

    [Fact]
    public void PermissionKey_EqualityAndHashing_AreCanonical()
    {
        var k1 = PermissionKey.Parse("tenant.settings.update");
        var k2 = PermissionKey.Parse("tenant.settings.update");
        var k3 = PermissionKey.Parse("platform.tenants.approve");

        Assert.Equal(k1, k2);
        Assert.Equal(k1.GetHashCode(), k2.GetHashCode());
        Assert.True(k1 == k2);
        Assert.NotEqual(k1, k3);
        Assert.True(k1 != k3);
    }

    [Fact]
    public void PermissionKey_ScopeCompatibility_EnforcesStrictSeparation()
    {
        var platformKey = PermissionKey.Parse("platform.tenants.approve");
        var tenantKey = PermissionKey.Parse("tenant.settings.update");
        var tenantScope = AuthorizationScope.ForTenant(Guid.NewGuid());

        Assert.True(platformKey.IsCompatibleWith(AuthorizationScope.Platform));
        Assert.False(platformKey.IsCompatibleWith(tenantScope));
        platformKey.EnsureCompatibleWith(AuthorizationScope.Platform);
        Assert.Throws<InvalidOperationException>(() => platformKey.EnsureCompatibleWith(tenantScope));

        Assert.True(tenantKey.IsCompatibleWith(tenantScope));
        Assert.False(tenantKey.IsCompatibleWith(AuthorizationScope.Platform));
        tenantKey.EnsureCompatibleWith(tenantScope);
        Assert.Throws<InvalidOperationException>(() => tenantKey.EnsureCompatibleWith(AuthorizationScope.Platform));
    }

    [Fact]
    public void ExistingTenantRoles_RemainUnchangedByAuthorizationPrimitives()
    {
        // Creating domain primitives does not alter TenantMembershipRole or grant authority
        Assert.Equal(new[] { TenantMembershipRole.Owner, TenantMembershipRole.Administrator, TenantMembershipRole.Member },
            Enum.GetValues<TenantMembershipRole>());
    }
}
