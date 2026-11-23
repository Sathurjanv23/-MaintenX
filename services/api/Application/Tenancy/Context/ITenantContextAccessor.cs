namespace MaintenX.Api.Application.Tenancy.Context;

/// <summary>
/// Scoped accessor for retrieving the active <see cref="ITenantContext"/> of the current request.
/// </summary>
public interface ITenantContextAccessor
{
    /// <summary>
    /// Current verified tenant context for the request, or null if no tenant context has been resolved.
    /// </summary>
    ITenantContext? Current { get; }

    /// <summary>
    /// Indicates whether a valid verified tenant context is active for the current request.
    /// </summary>
    bool HasContext => Current != null;
}
