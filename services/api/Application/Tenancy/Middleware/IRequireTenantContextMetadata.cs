namespace MaintenX.Api.Application.Tenancy.Middleware;

/// <summary>
/// Marker metadata interface identifying endpoints that require an active, verified <see cref="MaintenX.Api.Application.Tenancy.Context.ITenantContext"/>.
/// </summary>
public interface IRequireTenantContextMetadata
{
}
