namespace MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Safe application data contract representing tenant organization details.
/// Excludes internal persistence implementation concerns and sensitive database internals.
/// </summary>
/// <param name="Id">Unique identifier of the tenant organization.</param>
/// <param name="Slug">Normalized URL slug identifier.</param>
/// <param name="DisplayName">Human-readable organization display name.</param>
/// <param name="Status">Operational lifecycle status of the organization.</param>
/// <param name="CreatedAtUtc">UTC timestamp of tenant creation.</param>
/// <param name="UpdatedAtUtc">UTC timestamp of the most recent update.</param>
/// <param name="Version">Optimistic concurrency token.</param>
public sealed record TenantResponse(
    Guid Id,
    string Slug,
    string DisplayName,
    string Status,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc,
    long Version);
