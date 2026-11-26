namespace MaintenX.Api.Domain.Authorization;

/// <summary>
/// Immutable definition of a registered authorization permission in <see cref="PermissionCatalog"/>.
/// </summary>
public sealed class PermissionDefinition : IEquatable<PermissionDefinition>
{
    /// <summary>
    /// Canonical permission identifier.
    /// </summary>
    public PermissionKey Key { get; }

    /// <summary>
    /// Explicit authorization scope boundary required by this permission.
    /// </summary>
    public AuthorizationScopeKind Scope => Key.Scope;

    /// <summary>
    /// Human-readable description of the capability represented by this permission.
    /// </summary>
    public string Description { get; }

    internal PermissionDefinition(PermissionKey key, string description)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);

        Key = key;
        Description = description.Trim();
    }

    public bool Equals(PermissionDefinition? other)
        => other is not null && Key.Equals(other.Key);

    public override bool Equals(object? obj) => Equals(obj as PermissionDefinition);

    public override int GetHashCode() => Key.GetHashCode();

    public override string ToString() => $"{Key.Value} ({Scope})";
}
