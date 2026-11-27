namespace MaintenX.Api.Application.Authorization.Contracts;

using MaintenX.Api.Domain.Authorization;

/// <summary>
/// Immutable, minimal authorization decision returned by <see cref="Services.IPlatformGrantResolver"/>.
/// Constructors are private/internal so callers cannot manufacture trusted authorization evidence.
/// </summary>
public sealed record PlatformGrantResolutionResult
{
    public bool IsAllowed { get; }
    public Guid? UserId { get; }
    public Guid? GrantId { get; }
    public PlatformRole? Role { get; }
    public PermissionKey? Permission { get; }
    public string? DenialReason { get; }

    private PlatformGrantResolutionResult(
        bool isAllowed,
        Guid? userId,
        Guid? grantId,
        PlatformRole? role,
        PermissionKey? permission,
        string? denialReason)
    {
        IsAllowed = isAllowed;
        UserId = userId;
        GrantId = grantId;
        Role = role;
        Permission = permission;
        DenialReason = denialReason;
    }

    internal static PlatformGrantResolutionResult Allow(
        Guid userId,
        Guid grantId,
        PlatformRole role,
        PermissionKey permission) =>
        new(
            isAllowed: true,
            userId: userId,
            grantId: grantId,
            role: role,
            permission: permission,
            denialReason: null);

    internal static PlatformGrantResolutionResult Deny(string reason, PermissionKey? permission = null) =>
        new(
            isAllowed: false,
            userId: null,
            grantId: null,
            role: null,
            permission: permission,
            denialReason: reason);
}
