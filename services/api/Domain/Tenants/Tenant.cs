namespace MaintenX.Api.Domain.Tenants;

using System.Text.RegularExpressions;

/// <summary>
/// Root tenant entity representing an organization or customer facility management entity.
/// Persisted in the dedicated 'platform' schema ('platform.tenants').
/// </summary>
public sealed partial class Tenant
{
    private static readonly Regex SlugRegex = new(
        @"^[a-z0-9]+(?:-[a-z0-9]+)*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

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
    /// Validates and normalizes an input string to conform to strict slug rules.
    /// Invariants: Non-empty, no leading or trailing whitespace, lowercase, 2-100 characters,
    /// lowercase alphanumeric and single hyphens, no leading or trailing hyphens, no consecutive hyphens.
    /// </summary>
    public static string NormalizeAndValidateSlug(string slug)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);

        if (slug != slug.Trim())
        {
            throw new ArgumentException(
                "Tenant slug must not contain leading or trailing whitespace.",
                nameof(slug));
        }

        var normalized = slug.ToLowerInvariant();

        if (normalized.Length < 2 || normalized.Length > 100)
        {
            throw new ArgumentException(
                $"Tenant slug must be between 2 and 100 characters in length. Supplied length was {normalized.Length}.",
                nameof(slug));
        }

        if (!SlugRegex.IsMatch(normalized))
        {
            throw new ArgumentException(
                $"Tenant slug '{slug}' is invalid. Slugs must contain only lowercase alphanumeric characters and single hyphens between words (e.g., 'acme-facility'). Whitespace, uppercase letters, leading/trailing hyphens, and symbols are not permitted.",
                nameof(slug));
        }

        return normalized;
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
        var validatedSlug = NormalizeAndValidateSlug(slug);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        var now = DateTime.UtcNow;

        return new Tenant
        {
            Id = Guid.NewGuid(),
            Slug = validatedSlug,
            DisplayName = displayName.Trim(),
            Status = status,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            Version = 1
        };
    }

    /// <summary>
    /// Indicates whether the tenant organization is currently active and fully operational.
    /// </summary>
    public bool IsActive => Status == TenantStatus.Active;

    /// <summary>
    /// Indicates whether the tenant organization can accept new memberships (active or in onboarding).
    /// </summary>
    public bool CanAcceptMembers => Status == TenantStatus.Active || Status == TenantStatus.PendingOnboarding;

    /// <summary>
    /// Activates the tenant organization from PendingOnboarding or Suspended status.
    /// </summary>
    /// <param name="utcNow">UTC timestamp of activation.</param>
    /// <exception cref="InvalidOperationException">Thrown if the tenant is permanently deactivated.</exception>
    public void Activate(DateTime utcNow)
    {
        if (Status == TenantStatus.Deactivated)
        {
            throw new InvalidOperationException($"Cannot activate tenant '{Id}' because it is permanently deactivated.");
        }

        if (Status == TenantStatus.Active)
        {
            return; // Idempotent
        }

        Status = TenantStatus.Active;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Temporarily suspends operations and access for the tenant organization.
    /// </summary>
    /// <param name="utcNow">UTC timestamp of suspension.</param>
    /// <exception cref="InvalidOperationException">Thrown if tenant is deactivated or not yet onboarded.</exception>
    public void Suspend(DateTime utcNow)
    {
        if (Status == TenantStatus.Deactivated)
        {
            throw new InvalidOperationException($"Cannot suspend tenant '{Id}' because it is permanently deactivated.");
        }

        if (Status == TenantStatus.PendingOnboarding)
        {
            throw new InvalidOperationException($"Cannot suspend tenant '{Id}' because it is in PendingOnboarding status and has not completed initial onboarding.");
        }

        if (Status == TenantStatus.Suspended)
        {
            return; // Idempotent
        }

        Status = TenantStatus.Suspended;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Permanently deactivates the tenant organization. Deactivation is a terminal lifecycle state.
    /// </summary>
    /// <param name="utcNow">UTC timestamp of deactivation.</param>
    public void Deactivate(DateTime utcNow)
    {
        if (Status == TenantStatus.Deactivated)
        {
            return; // Idempotent
        }

        Status = TenantStatus.Deactivated;
        UpdatedAtUtc = utcNow;
        Version++;
    }

    /// <summary>
    /// Updates the display name of the tenant organization.
    /// </summary>
    /// <param name="displayName">New display name.</param>
    /// <param name="utcNow">UTC timestamp of the update.</param>
    /// <exception cref="ArgumentException">Thrown if displayName is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">Thrown if tenant is deactivated.</exception>
    public void UpdateDisplayName(string displayName, DateTime utcNow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        if (Status == TenantStatus.Deactivated)
        {
            throw new InvalidOperationException($"Cannot update display name for deactivated tenant '{Id}'.");
        }

        var trimmed = displayName.Trim();
        if (DisplayName == trimmed)
        {
            return; // Idempotent
        }

        DisplayName = trimmed;
        UpdatedAtUtc = utcNow;
        Version++;
    }
}
