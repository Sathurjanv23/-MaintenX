namespace MaintenX.Api.Application.Authorization.Services;

using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Domain.Authorization;

/// <summary>
/// Server-side authoritative resolver that evaluates persisted <see cref="PlatformRoleGrant"/> records
/// against a server-controlled <c>Bearer</c> authentication result, current account eligibility,
/// current session validity, and registered platform-scoped permissions.
/// </summary>
public interface IPlatformGrantResolver
{
    /// <summary>
    /// Evaluates whether the current server-authenticated <c>Bearer</c> caller holds an active,
    /// authoritative platform role grant permitting <paramref name="permission"/>.
    /// </summary>
    Task<PlatformGrantResolutionResult> ResolveAsync(
        PermissionKey? permission,
        CancellationToken cancellationToken = default);
}
