namespace MaintenX.Api.Application.Authorization.Policies;

using MaintenX.Api.Application.Authorization.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

/// <summary>
/// Server-side authorization handler evaluating <see cref="PlatformPermissionRequirement"/>
/// against <see cref="IPlatformGrantResolver"/>.
/// Enforces fail-closed evaluation: caller-supplied claims or headers cannot satisfy this requirement.
/// </summary>
public sealed class PlatformPermissionHandler : AuthorizationHandler<PlatformPermissionRequirement>
{
    private readonly IPlatformGrantResolver _platformGrantResolver;
    private readonly ILogger<PlatformPermissionHandler> _logger;

    public PlatformPermissionHandler(
        IPlatformGrantResolver platformGrantResolver,
        ILogger<PlatformPermissionHandler> logger)
    {
        _platformGrantResolver = platformGrantResolver ?? throw new ArgumentNullException(nameof(platformGrantResolver));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PlatformPermissionRequirement requirement)
    {
        var result = await _platformGrantResolver.ResolveAsync(requirement.Permission);
        if (result.IsAllowed)
        {
            context.Succeed(requirement);
        }
        else
        {
            _logger.LogWarning("Platform authorization denied for permission {Permission}. Reason: {Reason}",
                requirement.Permission.Value, result.DenialReason);
        }
    }
}
