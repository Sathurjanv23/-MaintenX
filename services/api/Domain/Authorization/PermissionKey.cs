namespace MaintenX.Api.Domain.Authorization;

using System.Text.RegularExpressions;

/// <summary>
/// Immutable, strongly validated canonical permission identifier value object
/// (e.g., <c>platform.tenants.approve</c>, <c>tenant.settings.update</c>).
/// <para>
/// A valid <see cref="PermissionKey"/> represents only a syntactically valid identifier and its
/// required scope boundary. It does NOT establish that the permission exists in an approved catalog
/// or is granted to any caller. Unknown permissions must always be denied by default.
/// </para>
/// </summary>
public sealed partial class PermissionKey : IEquatable<PermissionKey>
{
    public const int MinLength = 8;
    public const int MaxLength = 100;

    private const string PlatformPrefix = "platform.";
    private const string TenantPrefix = "tenant.";

    [GeneratedRegex(@"^(?:platform|tenant)(?:\.[a-z][a-z0-9_-]*){1,4}$", RegexOptions.CultureInvariant)]
    private static partial Regex CanonicalPattern();

    /// <summary>
    /// Canonical lowercase dot-separated permission identifier.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Explicit authorization scope required by this permission identifier.
    /// </summary>
    public AuthorizationScopeKind Scope { get; }

    private PermissionKey(string value, AuthorizationScopeKind scope)
    {
        Value = value;
        Scope = scope;
    }

    /// <summary>
    /// Parses and validates a canonical permission identifier.
    /// Rejects null, empty, whitespace, uppercase, wildcards, ambiguous prefixes, and oversized strings.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when <paramref name="rawKey"/> violates canonical permission identifier rules.</exception>
    public static PermissionKey Parse(string? rawKey)
    {
        if (!TryParse(rawKey, out var parsed, out var error))
        {
            throw new ArgumentException(error, nameof(rawKey));
        }

        return parsed!;
    }

    /// <summary>
    /// Attempts to parse a canonical permission identifier without throwing on invalid input.
    /// </summary>
    public static bool TryParse(string? rawKey, out PermissionKey? permissionKey)
        => TryParse(rawKey, out permissionKey, out _);

    private static bool TryParse(string? rawKey, out PermissionKey? permissionKey, out string error)
    {
        permissionKey = null;

        if (string.IsNullOrWhiteSpace(rawKey))
        {
            error = "Permission identifier cannot be null, empty, or whitespace.";
            return false;
        }

        if (rawKey.Length != rawKey.Trim().Length)
        {
            error = "Permission identifier must not contain leading or trailing whitespace.";
            return false;
        }

        if (rawKey.Length < MinLength || rawKey.Length > MaxLength)
        {
            error = $"Permission identifier length must be between {MinLength} and {MaxLength} characters.";
            return false;
        }

        if (rawKey.Contains('*', StringComparison.Ordinal))
        {
            error = "Wildcard permission identifiers are strictly prohibited.";
            return false;
        }

        if (!CanonicalPattern().IsMatch(rawKey))
        {
            error = $"Permission identifier '{rawKey}' is malformed. Expected lowercase dot-separated format prefixed with 'platform.' or 'tenant.' (e.g., 'tenant.settings.update').";
            return false;
        }

        AuthorizationScopeKind scope;
        if (rawKey.StartsWith(PlatformPrefix, StringComparison.Ordinal))
        {
            scope = AuthorizationScopeKind.Platform;
        }
        else if (rawKey.StartsWith(TenantPrefix, StringComparison.Ordinal))
        {
            scope = AuthorizationScopeKind.Tenant;
        }
        else
        {
            error = "Permission identifier must begin with an explicit 'platform.' or 'tenant.' scope prefix.";
            return false;
        }

        error = string.Empty;
        permissionKey = new PermissionKey(rawKey, scope);
        return true;
    }

    /// <summary>
    /// Returns <c>true</c> if this permission's required scope matches <paramref name="scope"/>.
    /// </summary>
    public bool IsCompatibleWith(AuthorizationScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Scope == scope.Kind;
    }

    /// <summary>
    /// Enforces that this permission identifier matches the target <paramref name="scope"/>,
    /// throwing <see cref="InvalidOperationException"/> on scope mismatch.
    /// </summary>
    public void EnsureCompatibleWith(AuthorizationScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (Scope != scope.Kind)
        {
            throw new InvalidOperationException(
                $"Authorization scope mismatch: permission '{Value}' requires '{Scope}' scope, but target scope is '{scope.Kind}'.");
        }
    }

    public bool Equals(PermissionKey? other)
        => other is not null && string.Equals(Value, other.Value, StringComparison.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as PermissionKey);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    public static bool operator ==(PermissionKey? left, PermissionKey? right)
        => Equals(left, right);

    public static bool operator !=(PermissionKey? left, PermissionKey? right)
        => !Equals(left, right);

    public override string ToString() => Value;
}
