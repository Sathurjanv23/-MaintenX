namespace MaintenX.Api.Common.Security;

/// <summary>
/// Policy names for tenancy rate-limiting endpoints.
/// </summary>
public static class TenancyRateLimitPolicies
{
    /// <summary>
    /// Rate limit policy for tenant creation / onboarding endpoints (5 requests/minute/user).
    /// </summary>
    public const string Onboarding = "Tenancy.Onboarding";

    /// <summary>
    /// Rate limit policy for standard authenticated tenant discovery, lookup, and settings endpoints (30 requests/minute/user).
    /// </summary>
    public const string Standard = "Tenancy.Standard";
}
