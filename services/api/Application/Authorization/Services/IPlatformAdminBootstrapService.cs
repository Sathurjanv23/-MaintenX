namespace MaintenX.Api.Application.Authorization.Services;

using MaintenX.Api.Application.Authorization.Contracts;

/// <summary>
/// Coordinates secure, idempotent, globally locked provisioning of the first Platform Administrator.
/// </summary>
public interface IPlatformAdminBootstrapService
{
    Task<PlatformAdminBootstrapResult> BootstrapAsync(
        PlatformAdminBootstrapRequest request,
        CancellationToken cancellationToken = default);
}
