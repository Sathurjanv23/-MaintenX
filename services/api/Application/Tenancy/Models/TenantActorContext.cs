namespace MaintenX.Api.Application.Tenancy.Models;

using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Domain.Tenants;

/// <summary>
/// Server-verified execution context representing the authenticated actor invoking tenancy operations.
/// Prevents reliance on client-declared unverified headers, parameters, or arbitrary claims.
/// </summary>
public sealed record TenantActorContext(
    Guid UserId,
    bool IsPlatformAdmin = false,
    Guid? TenantId = null,
    TenantMembershipRole? Role = null)
{
    /// <summary>
    /// Creates an actor context for a verified user without explicit tenant context or platform admin privileges.
    /// </summary>
    public static TenantActorContext FromUser(Guid userId, bool isPlatformAdmin = false) =>
        new(userId, IsPlatformAdmin: isPlatformAdmin);

    /// <summary>
    /// Creates an actor context representing a verified platform administrator.
    /// </summary>
    public static TenantActorContext PlatformAdmin(Guid userId) =>
        new(userId, IsPlatformAdmin: true);

    /// <summary>
    /// Creates an actor context representing a verified member of a specific tenant organization.
    /// </summary>
    public static TenantActorContext Member(
        Guid userId,
        Guid tenantId,
        TenantMembershipRole role = TenantMembershipRole.Member) =>
        new(userId, IsPlatformAdmin: false, TenantId: tenantId, Role: role);

    /// <summary>
    /// Safely projects an active request-scoped <see cref="ITenantContext"/> into a <see cref="TenantActorContext"/>.
    /// Returns null if no verified tenant context is active for the current request.
    /// </summary>
    public static TenantActorContext? FromTenantContext(ITenantContext? context) =>
        context is null
            ? null
            : new TenantActorContext(context.UserId, IsPlatformAdmin: false, context.TenantId, context.Role);
}
