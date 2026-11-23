namespace MaintenX.Api.Domain.Tenants;

/// <summary>
/// Defines the tenant ownership contract for domain entities.
/// Guarantees that any entity scoped to a tenant organization carries an explicit TenantId
/// for multi-tenant isolation, automatic query filtering, and write-side boundary enforcement.
/// </summary>
public interface ITenantEntity
{
    /// <summary>
    /// Identifier of the tenant organization that owns this entity.
    /// </summary>
    Guid TenantId { get; }
}
