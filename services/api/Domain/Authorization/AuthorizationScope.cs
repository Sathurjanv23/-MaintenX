namespace MaintenX.Api.Domain.Authorization;

/// <summary>
/// Immutable domain value object representing an explicit authorization target scope
/// (<see cref="AuthorizationScopeKind.Platform"/> or <see cref="AuthorizationScopeKind.Tenant"/> with a non-empty <see cref="TenantId"/>).
/// <para>
/// A scope value represents only an authorization boundary target; it is never proof of
/// authenticated identity or granted permission.
/// </para>
/// </summary>
public sealed class AuthorizationScope : IEquatable<AuthorizationScope>
{
    /// <summary>
    /// Singleton representing the global platform authorization scope.
    /// </summary>
    public static AuthorizationScope Platform { get; } = new(AuthorizationScopeKind.Platform, null);

    /// <summary>
    /// Discriminator identifying whether this scope targets platform-level or tenant-level authority.
    /// </summary>
    public AuthorizationScopeKind Kind { get; }

    /// <summary>
    /// Target tenant identifier when <see cref="Kind"/> is <see cref="AuthorizationScopeKind.Tenant"/>;
    /// always <c>null</c> when <see cref="Kind"/> is <see cref="AuthorizationScopeKind.Platform"/>.
    /// </summary>
    public Guid? TenantId { get; }

    /// <summary>
    /// Indicates whether this scope is global platform scope.
    /// </summary>
    public bool IsPlatform => Kind == AuthorizationScopeKind.Platform;

    /// <summary>
    /// Indicates whether this scope targets a specific tenant organization.
    /// </summary>
    public bool IsTenant => Kind == AuthorizationScopeKind.Tenant;

    private AuthorizationScope(AuthorizationScopeKind kind, Guid? tenantId)
    {
        Kind = kind;
        TenantId = tenantId;
    }

    /// <summary>
    /// Creates a tenant-scoped <see cref="AuthorizationScope"/> bound to the specified non-empty tenant identifier.
    /// </summary>
    /// <param name="tenantId">Non-empty identifier of the target tenant.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="tenantId"/> is <see cref="Guid.Empty"/>.</exception>
    public static AuthorizationScope ForTenant(Guid tenantId)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("Tenant authorization scope requires a non-empty TenantId.", nameof(tenantId));
        }

        return new AuthorizationScope(AuthorizationScopeKind.Tenant, tenantId);
    }

    /// <summary>
    /// Creates a validated <see cref="AuthorizationScope"/> for the given kind and optional tenant identifier.
    /// Rejects undefined scope kinds, platform scopes with a tenant identifier, and tenant scopes without a valid tenant identifier.
    /// </summary>
    public static AuthorizationScope Create(AuthorizationScopeKind kind, Guid? tenantId = null)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentException($"Invalid authorization scope kind: '{kind}'.", nameof(kind));
        }

        if (kind == AuthorizationScopeKind.Platform)
        {
            if (tenantId.HasValue)
            {
                throw new ArgumentException(
                    "Platform authorization scope must not specify a TenantId.",
                    nameof(tenantId));
            }

            return Platform;
        }

        if (!tenantId.HasValue || tenantId.Value == Guid.Empty)
        {
            throw new ArgumentException(
                "Tenant authorization scope requires a non-empty TenantId.",
                nameof(tenantId));
        }

        return new AuthorizationScope(AuthorizationScopeKind.Tenant, tenantId.Value);
    }

    public bool Equals(AuthorizationScope? other)
    {
        if (other is null)
        {
            return false;
        }

        return Kind == other.Kind && TenantId == other.TenantId;
    }

    public override bool Equals(object? obj) => Equals(obj as AuthorizationScope);

    public override int GetHashCode() => HashCode.Combine(Kind, TenantId);

    public static bool operator ==(AuthorizationScope? left, AuthorizationScope? right)
        => Equals(left, right);

    public static bool operator !=(AuthorizationScope? left, AuthorizationScope? right)
        => !Equals(left, right);

    public override string ToString()
        => IsPlatform ? "platform" : $"tenant:{TenantId}";
}
