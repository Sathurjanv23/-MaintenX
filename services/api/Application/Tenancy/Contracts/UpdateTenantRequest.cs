namespace MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Request payload for updating permitted tenant organization settings.
/// </summary>
/// <param name="DisplayName">Updated human-readable display name (2-100 chars).</param>
/// <param name="ExpectedVersion">Optional optimistic concurrency token. If provided, update is rejected if version differs.</param>
public sealed record UpdateTenantRequest(string DisplayName, long? ExpectedVersion = null);
