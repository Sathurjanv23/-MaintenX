namespace MaintenX.Api.Application.Authorization.Policies;

using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Domain.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

/// <summary>
/// Server-side authorization handler evaluating <see cref="TenantPermissionRequirement"/>
/// against the verified active tenant context in <see cref="ITenantContextAccessor"/>.
/// Guarantees that ordinary actors possess the required tenant role privilege,
/// while administrative bypass contexts are respected if established by a verified platform administrator.
/// </summary>
public sealed class TenantPermissionHandler : AuthorizationHandler<TenantPermissionRequirement>
{
    private readonly ITenantContextAccessor _tenantContextAccessor;
    private readonly ILogger<TenantPermissionHandler> _logger;

    public TenantPermissionHandler(
        ITenantContextAccessor tenantContextAccessor,
        ILogger<TenantPermissionHandler> logger)
    {
        _tenantContextAccessor = tenantContextAccessor ?? throw new ArgumentNullException(nameof(tenantContextAccessor));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        TenantPermissionRequirement requirement)
    {
        var currentContext = _tenantContextAccessor.Current;
        if (currentContext is null)
        {
            _logger.LogWarning("Tenant authorization denied for permission {Permission}: no active verified tenant context.",
                requirement.Permission.Value);
            return Task.CompletedTask;
        }

        if (TenantRolePermissionMap.HasPermission(currentContext.Role, requirement.Permission))
        {
            context.Succeed(requirement);
        }
        else
        {
            _logger.LogWarning("Tenant authorization denied for permission {Permission}: Role {Role} in Tenant {TenantId} lacks required privilege.",
                requirement.Permission.Value, currentContext.Role, currentContext.TenantId);
        }

        return Task.CompletedTask;
    }
}
