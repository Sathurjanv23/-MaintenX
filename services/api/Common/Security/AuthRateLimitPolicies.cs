namespace MaintenX.Api.Common.Security;

/// <summary>
/// Policy names for authentication rate-limiting endpoints.
/// </summary>
public static class AuthRateLimitPolicies
{
    /// <summary>
    /// Rate limit policy for user registration endpoints (5 requests/minute/IP).
    /// </summary>
    public const string Registration = "Auth.Registration";

    /// <summary>
    /// Rate limit policy for user login endpoints (10 requests/minute/IP).
    /// </summary>
    public const string Login = "Auth.Login";

    /// <summary>
    /// Rate limit policy for token refresh endpoints (30 requests/minute/IP).
    /// </summary>
    public const string Refresh = "Auth.Refresh";
}

