namespace MaintenX.Api.Application.Authorization.Services;

using MaintenX.Api.Application.Authorization.Contracts;

/// <summary>
/// Server-side operational authorization boundary for initial Platform Administrator bootstrap.
/// Derives authorization and operator identity from the restricted operational execution environment,
/// never from caller-supplied flags or HTTP request inputs.
/// </summary>
public interface IBootstrapOperatorAuthorizationProvider
{
    Task<BootstrapOperatorAuthorizationResult> AuthorizeAsync(CancellationToken cancellationToken = default);
}
