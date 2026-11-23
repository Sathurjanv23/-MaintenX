namespace MaintenX.Api.Application.Tenancy.Resolution;

using System.Security.Claims;

/// <summary>
/// Service responsible for securely validating and resolving tenant context for an authenticated user.
/// Enforces multi-tier checks against user identity, active session, security stamp, tenant lifecycle,
/// and user membership status before granting tenant access.
/// </summary>
public interface ITenantResolutionService
{
    /// <summary>
    /// Resolves and verifies tenant context for the specified user and requested tenant identifier.
    /// </summary>
    /// <param name="user">The claims principal representing the authenticated caller.</param>
    /// <param name="requestedTenantIdentifier">The tenant identifier provided by the caller (Guid or Slug).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantResolutionResult"/> indicating success or explicit failure details.</returns>
    Task<TenantResolutionResult> ResolveAsync(
        ClaimsPrincipal? user,
        string? requestedTenantIdentifier,
        CancellationToken cancellationToken = default);
}
