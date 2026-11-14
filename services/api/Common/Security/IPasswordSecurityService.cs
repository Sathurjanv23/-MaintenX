namespace MaintenX.Api.Common.Security;

using MaintenX.Api.Domain.Auth;
using Microsoft.AspNetCore.Identity;

/// <summary>
/// Provides cryptographic password hashing, verification, transparent rehash detection,
/// and timing-attack mitigation via constant-time dummy hashing for nonexistent users.
/// </summary>
public interface IPasswordSecurityService
{
    /// <summary>
    /// Hashes the supplied plaintext password using the configured ASP.NET Core password hashing implementation.
    /// </summary>
    /// <param name="user">The user entity context for salt and identity binding.</param>
    /// <param name="password">Plaintext password to hash.</param>
    /// <returns>Cryptographic password hash string.</returns>
    string HashPassword(User user, string password);

    /// <summary>
    /// Verifies the provided password against a stored cryptographic password hash.
    /// Returns <see cref="PasswordVerificationResult.Success"/> on match,
    /// <see cref="PasswordVerificationResult.SuccessRehashNeeded"/> if the hash algorithm or iteration count was upgraded,
    /// or <see cref="PasswordVerificationResult.Failed"/> on mismatch.
    /// </summary>
    /// <param name="user">The user entity context.</param>
    /// <param name="hashedPassword">The stored cryptographic password hash.</param>
    /// <param name="providedPassword">The plaintext password provided by the user.</param>
    /// <returns>A <see cref="PasswordVerificationResult"/> indicating success, failure, or rehash requirement.</returns>
    PasswordVerificationResult VerifyHashedPassword(User user, string hashedPassword, string providedPassword);

    /// <summary>
    /// Determines whether the password verification result indicates that a transparent password rehash is needed.
    /// When true, the password hash should be updated without rotating the user's security stamp.
    /// </summary>
    /// <param name="result">The result from <see cref="VerifyHashedPassword"/>.</param>
    /// <returns>True if a rehash is required; otherwise false.</returns>
    bool NeedsRehash(PasswordVerificationResult result);

    /// <summary>
    /// Performs constant-time dummy password verification for nonexistent users during authentication.
    /// Consumes the exact same CPU work (PBKDF2 HMAC-SHA256 iterations) as genuine verification,
    /// preventing account enumeration via side-channel timing analysis.
    /// </summary>
    /// <param name="providedPassword">The plaintext password provided during authentication.</param>
    void VerifyDummyPassword(string providedPassword);

    /// <summary>
    /// Gets the precomputed dummy password hash used for nonexistent user timing attack mitigation.
    /// </summary>
    string DummyHash { get; }
}
