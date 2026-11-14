namespace MaintenX.Api.Application.Auth.Models;

/// <summary>
/// Result of refresh token rotation. Distinguishes normal success, token replay attack detection, and failure.
/// </summary>
public sealed record RefreshTokenResult(
    bool IsSuccess,
    AuthTokenResult? Tokens,
    bool IsReplayDetected,
    string? ErrorMessage)
{
    public static RefreshTokenResult Success(AuthTokenResult tokens) =>
        new(true, tokens, false, null);

    public static RefreshTokenResult ReplayDetected(string message = "Token replay detected. All active tokens in this session have been revoked.") =>
        new(false, null, true, message);

    public static RefreshTokenResult Failed(string message) =>
        new(false, null, false, message);

    /// <summary>
    /// Redacts tokens and secret details from string representation.
    /// </summary>
    public override string ToString() =>
        $"RefreshTokenResult [IsSuccess={IsSuccess}, IsReplayDetected={IsReplayDetected}, ErrorMessage={ErrorMessage}]";
}
