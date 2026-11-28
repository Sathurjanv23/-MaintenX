namespace MaintenX.Api.Application.Authorization.Services;

using MaintenX.Api.Application.Authorization.Contracts;

/// <summary>
/// Application service coordinating authoritative platform role grant lifecycle operations
/// including secure internal revocation, global concurrency lock coordination, and durable audit trails.
/// </summary>
public interface IPlatformGrantService
{
    /// <summary>
    /// Revokes an active platform role grant with server-side authority validation,
    /// last-administrator protection, advisory lock serialization, and atomic audit logging.
    /// </summary>
    Task<PlatformGrantRevocationResult> RevokeGrantAsync(
        PlatformGrantRevocationRequest request,
        CancellationToken cancellationToken = default);
}
