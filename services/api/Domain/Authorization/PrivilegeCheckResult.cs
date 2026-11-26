namespace MaintenX.Api.Domain.Authorization;

/// <summary>
/// Immutable domain eligibility outcome for privilege assignment and lifecycle invariants.
/// </summary>
public sealed class PrivilegeCheckResult
{
    public bool IsAllowed { get; }
    public string? DenialReason { get; }

    private PrivilegeCheckResult(bool isAllowed, string? denialReason)
    {
        IsAllowed = isAllowed;
        DenialReason = denialReason;
    }

    public static PrivilegeCheckResult Allowed() => new(true, null);

    public static PrivilegeCheckResult Denied(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new PrivilegeCheckResult(false, reason.Trim());
    }
}
