namespace MaintenX.Api.Domain.Tenants;

/// <summary>
/// Root tenant entity representing an organization or customer facility management entity.
/// Persisted in the dedicated 'platform' schema ('platform.tenants').
/// </summary>
public sealed class Tenant
{
    /// <summary>
    /// Unique UUID primary key for the tenant.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Normalized unique URL slug for the tenant organization (lowercase alphanumeric and hyphens).
    /// </summary>
    public string Slug { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable display name of the tenant organization.
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Operational status of the tenant organization.
    /// </summary>
    public TenantStatus Status { get; set; } = TenantStatus.PendingOnboarding;

    /// <summary>
    /// UTC timestamp of entity creation.
    /// </summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>
    /// UTC timestamp of the most recent update.
    /// </summary>
    public DateTime UpdatedAtUtc { get; set; }

    /// <summary>
    /// Optimistic concurrency token tracking row mutations.
    /// </summary>
    public long Version { get; set; }

    /// <summary>
    /// Parameterless constructor required by EF Core.
    /// </summary>
    public Tenant()
    {
    }

    /// <summary>
    /// Factory method for instantiating a new Tenant with normalized invariants.
    /// </summary>
    /// <param name="slug">Organization slug identifier.</param>
    /// <param name="displayName">Human-readable organization name.</param>
    /// <param name="status">Initial lifecycle status.</param>
    /// <returns>A validated Tenant instance.</returns>
    public static Tenant Create(string slug, string displayName, TenantStatus status = TenantStatus.PendingOnboarding)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        var normalizedSlug = slug.Trim().ToLowerInvariant();
        var now = DateTime.UtcNow;

        return new Tenant
        {
            Id = Guid.NewGuid(),
            Slug = normalizedSlug,
            DisplayName = displayName.Trim(),
            Status = status,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            Version = 1
        };
    }
}
