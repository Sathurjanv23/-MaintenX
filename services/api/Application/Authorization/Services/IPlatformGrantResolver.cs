namespace MaintenX.Api.Application.Authorization.Services;

using System.Security.Claims;
using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Domain.Authorization;

/// <summary>
/// Server-side authoritative resolver that evaluates persisted <see cref="PlatformRoleGrant"/> records
/// against verified authenticated identity, current account eligibility, current session validity,
/// and registered platform-scoped permissions.
/// </summary>
public interface IPlatformGrantResolver
{
    /// <summary>
    /// Evaluates whether <paramref name="principal"/> currently holds an active, authoritative
    /// platform role grant permitting <paramref name="permission"/>.
    /// </summary>
    Task<PlatformGrantResolutionResult> ResolveAsync(
        ClaimsPrincipal? principal,
        PermissionKey? permission,
        CancellationToken cancellationToken = default);
}
