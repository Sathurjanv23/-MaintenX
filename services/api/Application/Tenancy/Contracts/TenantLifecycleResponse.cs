namespace MaintenX.Api.Application.Tenancy.Contracts;

/// <summary>
/// Response payload for tenant lifecycle state transitions (activate, suspend, deactivate).
/// </summary>
/// <param name="TenantId">Identifier of the target tenant organization.</param>
/// <param name="Status">Resulting lifecycle status after transition.</param>
/// <param name="UpdatedAtUtc">UTC timestamp when the lifecycle status transition was applied.</param>
public sealed record TenantLifecycleResponse(
    Guid TenantId,
    string Status,
    DateTime UpdatedAtUtc);
