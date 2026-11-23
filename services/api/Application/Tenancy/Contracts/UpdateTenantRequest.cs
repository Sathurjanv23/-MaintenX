namespace MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Request payload for updating permitted tenant organization settings.
/// </summary>
/// <param name="DisplayName">Updated human-readable display name (2-100 chars).</param>
public sealed record UpdateTenantRequest(string DisplayName);
