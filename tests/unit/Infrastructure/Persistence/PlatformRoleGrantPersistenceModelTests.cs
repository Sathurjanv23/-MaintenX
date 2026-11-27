namespace MaintenX.UnitTests.Infrastructure.Persistence;

using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Xunit;

/// <summary>
/// EF Core model metadata verification for <see cref="PlatformRoleGrant"/> (Task 4.2.1).
/// Verifies schema, table, columns, conversions, relationships, check constraints,
/// partial unique index, concurrency token, and absence of tenant query filters.
/// </summary>
public class PlatformRoleGrantPersistenceModelTests
{
    private static MaintenXDbContext CreateModelContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=dummy;Username=dummy;Password=dummy")
            .Options;

        return new MaintenXDbContext(options);
    }

    [Fact]
    public void PlatformRoleGrant_IsRegisteredInPlatformSchema_WithCorrectTableAndPrimaryKey()
    {
        using var context = CreateModelContext();
        var entityType = context.Model.FindEntityType(typeof(PlatformRoleGrant));

        Assert.NotNull(entityType);
        Assert.Equal("platform", entityType!.GetSchema());
        Assert.Equal("platform_role_grants", entityType.GetTableName());

        var pk = entityType.FindPrimaryKey();
        Assert.NotNull(pk);
        Assert.Equal("pk_platform_role_grants", pk!.GetName());
        var pkProp = Assert.Single(pk.Properties);
        Assert.Equal(nameof(PlatformRoleGrant.Id), pkProp.Name);
        Assert.Equal("id", pkProp.GetColumnName());
    }

    [Fact]
    public void PlatformRoleGrant_ColumnsConversionsAndConcurrencyToken_ConfiguredCorrectly()
    {
        using var context = CreateModelContext();
        var entityType = context.Model.FindEntityType(typeof(PlatformRoleGrant))!;

        var userId = entityType.FindProperty(nameof(PlatformRoleGrant.UserId))!;
        Assert.Equal("user_id", userId.GetColumnName());
        Assert.False(userId.IsNullable);

        var role = entityType.FindProperty(nameof(PlatformRoleGrant.Role))!;
        Assert.Equal("role", role.GetColumnName());
        Assert.Equal(50, role.GetMaxLength());
        Assert.False(role.IsNullable);
        Assert.NotNull(role.GetValueConverter() ?? role.FindTypeMapping()?.Converter);

        var status = entityType.FindProperty(nameof(PlatformRoleGrant.Status))!;
        Assert.Equal("status", status.GetColumnName());
        Assert.Equal(50, status.GetMaxLength());
        Assert.False(status.IsNullable);
        Assert.NotNull(status.GetValueConverter() ?? status.FindTypeMapping()?.Converter);

        var grantedAt = entityType.FindProperty(nameof(PlatformRoleGrant.GrantedAtUtc))!;
        Assert.Equal("granted_at_utc", grantedAt.GetColumnName());
        Assert.Equal("timestamp with time zone", grantedAt.GetColumnType());
        Assert.False(grantedAt.IsNullable);

        var grantedByActorKind = entityType.FindProperty(nameof(PlatformRoleGrant.GrantedByActorKind))!;
        Assert.Equal("granted_by_actor_kind", grantedByActorKind.GetColumnName());
        Assert.False(grantedByActorKind.IsNullable);

        var grantedBy = entityType.FindProperty(nameof(PlatformRoleGrant.GrantedByUserId))!;
        Assert.Equal("granted_by_user_id", grantedBy.GetColumnName());
        Assert.True(grantedBy.IsNullable);

        var grantedByOp = entityType.FindProperty(nameof(PlatformRoleGrant.GrantedByOperatorId))!;
        Assert.Equal("granted_by_operator_id", grantedByOp.GetColumnName());
        Assert.True(grantedByOp.IsNullable);

        var revokedAt = entityType.FindProperty(nameof(PlatformRoleGrant.RevokedAtUtc))!;
        Assert.Equal("revoked_at_utc", revokedAt.GetColumnName());
        Assert.Equal("timestamp with time zone", revokedAt.GetColumnType());
        Assert.True(revokedAt.IsNullable);

        var revokedBy = entityType.FindProperty(nameof(PlatformRoleGrant.RevokedByUserId))!;
        Assert.Equal("revoked_by_user_id", revokedBy.GetColumnName());
        Assert.True(revokedBy.IsNullable);

        var reason = entityType.FindProperty(nameof(PlatformRoleGrant.RevocationReason))!;
        Assert.Equal("revocation_reason", reason.GetColumnName());
        Assert.Equal(PlatformRoleGrant.MaxRevocationReasonLength, reason.GetMaxLength());
        Assert.True(reason.IsNullable);

        var version = entityType.FindProperty(nameof(PlatformRoleGrant.Version))!;
        Assert.Equal("version", version.GetColumnName());
        Assert.False(version.IsNullable);
        Assert.True(version.IsConcurrencyToken);

        // IsActive is derived and must NOT be persisted
        Assert.Null(entityType.FindProperty(nameof(PlatformRoleGrant.IsActive)));
    }

    [Fact]
    public void PlatformRoleGrant_HasRestrictiveUserForeignKey_PartialUniqueIndex_AndCheckConstraints()
    {
        using var context = CreateModelContext();
        var designModel = context.GetService<IDesignTimeModel>().Model;
        var entityType = designModel.FindEntityType(typeof(PlatformRoleGrant))!;

        var fk = Assert.Single(entityType.GetForeignKeys());
        Assert.Equal(typeof(User), fk.PrincipalEntityType.ClrType);
        Assert.Equal("fk_platform_role_grants_users_user_id", fk.GetConstraintName());
        Assert.Equal(DeleteBehavior.Restrict, fk.DeleteBehavior);

        var activeUniqueIndex = entityType.GetIndexes()
            .SingleOrDefault(i => i.GetDatabaseName() == "ix_platform_role_grants_user_id_role_active");
        Assert.NotNull(activeUniqueIndex);
        Assert.True(activeUniqueIndex!.IsUnique);
        Assert.Equal("status = 'Active'", activeUniqueIndex.GetFilter());
        Assert.Equal(new[] { nameof(PlatformRoleGrant.UserId), nameof(PlatformRoleGrant.Role) },
            activeUniqueIndex.Properties.Select(p => p.Name).ToArray());

        var checkNames = entityType.GetCheckConstraints().Select(c => c.Name).ToHashSet();
        Assert.Contains("ck_platform_role_grants_id_non_empty", checkNames);
        Assert.Contains("ck_platform_role_grants_user_id_non_empty", checkNames);
        Assert.Contains("ck_platform_role_grants_granted_by_actor_kind", checkNames);
        Assert.Contains("ck_platform_role_grants_granted_actor_consistency", checkNames);
        Assert.Contains("ck_platform_role_grants_role", checkNames);
        Assert.Contains("ck_platform_role_grants_status", checkNames);
        Assert.Contains("ck_platform_role_grants_version_positive", checkNames);
        Assert.Contains("ck_platform_role_grants_revocation_consistency", checkNames);
    }

    [Fact]
    public void PlatformRoleGrant_IsGlobalAndNotTenantScoped_WhileTenantFiltersRemainIntact()
    {
        using var context = CreateModelContext();
        var grantType = context.Model.FindEntityType(typeof(PlatformRoleGrant))!;
        var membershipType = context.Model.FindEntityType(typeof(TenantMembership))!;

        Assert.False(typeof(ITenantEntity).IsAssignableFrom(typeof(PlatformRoleGrant)));
        Assert.Null(grantType.FindProperty("TenantId"));
        Assert.Empty(grantType.GetDeclaredQueryFilters());

        // Existing ITenantEntity query filter remains intact
        Assert.NotEmpty(membershipType.GetDeclaredQueryFilters());
    }
}
