namespace MaintenX.Api.Application.Tenancy.Validation;

using System.Text.RegularExpressions;

/// <summary>
/// Static validation service enforcing domain and application-layer invariants for tenants and memberships.
/// Provides safe input validation, bounds checking, and normalized string handling.
/// </summary>
public static partial class TenantValidation
{
    public const int MinSlugLength = 2;
    public const int MaxSlugLength = 100;

    public const int MinDisplayNameLength = 2;
    public const int MaxDisplayNameLength = 100;

    public const int MinReasonLength = 3;
    public const int MaxReasonLength = 500;

    private static readonly Regex SlugPattern = new(
        @"^[a-z0-9]+(?:-[a-z0-9]+)*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Validates and normalizes an input URL slug string.
    /// Invariants: Non-empty, no leading/trailing whitespace, 2-100 characters, lowercase alphanumeric and single hyphens.
    /// </summary>
    /// <param name="slug">Candidate slug string.</param>
    /// <returns>Normalized lowercase slug.</returns>
    /// <exception cref="ArgumentException">Thrown when candidate slug violates length, character, or format rules.</exception>
    public static string ValidateAndNormalizeSlug(string? slug)
    {
        if (string.IsNullOrWhiteSpace(slug))
        {
            throw new ArgumentException("Tenant slug cannot be null, empty, or consist solely of whitespace.", nameof(slug));
        }

        if (slug != slug.Trim())
        {
            throw new ArgumentException("Tenant slug must not contain leading or trailing whitespace.", nameof(slug));
        }

        var normalized = slug.ToLowerInvariant();

        if (normalized.Length < MinSlugLength || normalized.Length > MaxSlugLength)
        {
            throw new ArgumentException(
                $"Tenant slug must be between {MinSlugLength} and {MaxSlugLength} characters in length. Supplied length was {normalized.Length}.",
                nameof(slug));
        }

        if (!SlugPattern.IsMatch(normalized))
        {
            throw new ArgumentException(
                $"Tenant slug '{slug}' is invalid. Slugs must contain only lowercase alphanumeric characters and single hyphens between words (e.g., 'acme-corp'). Whitespace, uppercase letters, leading/trailing hyphens, consecutive hyphens, and symbols are not permitted.",
                nameof(slug));
        }

        return normalized;
    }

    /// <summary>
    /// Validates and trims an organization display name string.
    /// Invariants: Non-empty, trimmed length between 2 and 100 characters.
    /// </summary>
    /// <param name="displayName">Candidate display name.</param>
    /// <returns>Trimmed display name.</returns>
    /// <exception cref="ArgumentException">Thrown when display name is null, empty, whitespace, or outside length constraints.</exception>
    public static string ValidateAndTrimDisplayName(string? displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName))
        {
            throw new ArgumentException("Tenant display name cannot be null, empty, or consist solely of whitespace.", nameof(displayName));
        }

        var trimmed = displayName.Trim();

        if (trimmed.Length < MinDisplayNameLength || trimmed.Length > MaxDisplayNameLength)
        {
            throw new ArgumentException(
                $"Tenant display name must be between {MinDisplayNameLength} and {MaxDisplayNameLength} characters in length. Supplied length was {trimmed.Length}.",
                nameof(displayName));
        }

        return trimmed;
    }

    /// <summary>
    /// Validates that an entity identifier is non-empty.
    /// </summary>
    /// <param name="tenantId">Tenant unique identifier.</param>
    /// <exception cref="ArgumentException">Thrown when tenantId is Guid.Empty.</exception>
    public static void ValidateTenantId(Guid tenantId)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("Tenant identifier cannot be an empty GUID.", nameof(tenantId));
        }
    }

    /// <summary>
    /// Validates that a user identifier is non-empty.
    /// </summary>
    /// <param name="userId">User unique identifier.</param>
    /// <exception cref="ArgumentException">Thrown when userId is Guid.Empty.</exception>
    public static void ValidateUserId(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User identifier cannot be an empty GUID.", nameof(userId));
        }
    }

    /// <summary>
    /// Validates an administrative reason for lifecycle state mutations (e.g. suspension, deactivation).
    /// </summary>
    /// <param name="reason">Administrative reason string.</param>
    /// <param name="paramName">Parameter name for exception reporting.</param>
    /// <returns>Trimmed reason string.</returns>
    /// <exception cref="ArgumentException">Thrown when reason is null, empty, whitespace, or outside length bounds (3-500 chars).</exception>
    public static string ValidateReason(string? reason, string paramName = "reason")
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("An administrative reason must be provided for lifecycle state transitions.", paramName);
        }

        var trimmed = reason.Trim();

        if (trimmed.Length < MinReasonLength || trimmed.Length > MaxReasonLength)
        {
            throw new ArgumentException(
                $"Administrative reason must be between {MinReasonLength} and {MaxReasonLength} characters. Supplied length was {trimmed.Length}.",
                paramName);
        }

        return trimmed;
    }
}
