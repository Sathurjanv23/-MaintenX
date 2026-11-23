namespace MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Request payload for creating and onboarding a new tenant organization.
/// </summary>
/// <param name="Slug">Unique URL identifier slug for the tenant (lowercase alphanumeric with hyphens, 2-100 chars).</param>
/// <param name="DisplayName">Human-readable organization display name (2-100 chars).</param>
public sealed record CreateTenantRequest(string Slug, string DisplayName);
