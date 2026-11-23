namespace MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Response payload returned after successful tenant creation and onboarding initialization.
/// </summary>
/// <param name="TenantId">Unique identifier of the newly created tenant organization.</param>
/// <param name="Slug">Normalized URL slug of the tenant organization.</param>
/// <param name="DisplayName">Display name of the tenant organization.</param>
/// <param name="Status">Initial operational status of the tenant organization (e.g. Active or PendingOnboarding).</param>
/// <param name="CreatedAtUtc">UTC timestamp when the organization was created.</param>
public sealed record CreateTenantResponse(
    Guid TenantId,
    string Slug,
    string DisplayName,
    string Status,
    DateTime CreatedAtUtc);
