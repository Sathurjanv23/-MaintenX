namespace MaintenX.UnitTests.Domain.Auth;

using MaintenX.Api.Domain.Auth;
using Xunit;

public class RefreshTokenTests
{
    private static readonly Guid ValidSessionId = Guid.NewGuid();
    private const string ValidHash1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const string ValidHash2 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays(30);

    [Fact]
    public void Create_WithValidParameters_InitializesEntityCorrectly()
    {
        var now = DateTime.UtcNow;
        var token = RefreshToken.Create(ValidSessionId, ValidHash1, now, DefaultLifetime);

        Assert.NotEqual(Guid.Empty, token.Id);
        Assert.Equal(ValidSessionId, token.SessionId);
        Assert.Equal(ValidHash1, token.TokenHash);
        Assert.Equal(now, token.CreatedAtUtc);
        Assert.Equal(now.Add(DefaultLifetime), token.ExpiresAtUtc);
        Assert.Null(token.RevokedAtUtc);
        Assert.Null(token.ReplacedByTokenHash);
        Assert.False(token.IsRotated);
        Assert.False(token.IsRevoked);
        Assert.False(token.IsReplay);
        Assert.True(token.IsActive(now));
        Assert.False(token.IsExpired(now));
    }

    [Theory]
    [InlineData("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", ValidHash1)]
    [InlineData("  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ", ValidHash1)]
    public void ValidateAndNormalizeHash_NormalizesToTrimmedLowercaseHex(string raw, string expected)
    {
        var normalized = RefreshToken.ValidateAndNormalizeHash(raw);
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("tooshort")]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85")] // 63 chars
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855aa")] // 66 chars
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8zz")] // 'zz' non-hex
    public void ValidateAndNormalizeHash_WithInvalidHashes_ThrowsArgumentException(string? invalidHash)
    {
        Assert.ThrowsAny<ArgumentException>(() => RefreshToken.ValidateAndNormalizeHash(invalidHash!));
    }

    [Fact]
    public void Create_WithEmptySessionId_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            RefreshToken.Create(Guid.Empty, ValidHash1, DateTime.UtcNow, DefaultLifetime));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-3600)]
    public void Create_WithNonPositiveLifetime_ThrowsArgumentException(int seconds)
    {
        Assert.Throws<ArgumentException>(() =>
            RefreshToken.Create(ValidSessionId, ValidHash1, DateTime.UtcNow, TimeSpan.FromSeconds(seconds)));
    }

    [Fact]
    public void IsExpired_EvaluatesAccuratelyAgainstExpiryBoundary()
    {
        var now = DateTime.UtcNow;
        var token = RefreshToken.Create(ValidSessionId, ValidHash1, now, TimeSpan.FromMinutes(10));
        var expiresAt = token.ExpiresAtUtc;

        Assert.False(token.IsExpired(expiresAt.AddSeconds(-1)));
        Assert.True(token.IsExpired(expiresAt));
        Assert.True(token.IsExpired(expiresAt.AddSeconds(1)));
    }

    [Fact]
    public void Rotate_WithValidSuccessor_SetsSuccessorHashAndMarksRevoked()
    {
        var now = DateTime.UtcNow;
        var token = RefreshToken.Create(ValidSessionId, ValidHash1, now, DefaultLifetime);

        token.Rotate(ValidHash2, now);

        Assert.True(token.IsRotated);
        Assert.True(token.IsRevoked);
        Assert.True(token.IsReplay);
        Assert.Equal(ValidHash2, token.ReplacedByTokenHash);
        Assert.Equal(now, token.RevokedAtUtc);
        Assert.False(token.IsActive(now));
    }

    [Fact]
    public void Rotate_WhenSuccessorEqualsCurrentHash_ThrowsInvalidOperationException()
    {
        var token = RefreshToken.Create(ValidSessionId, ValidHash1, DateTime.UtcNow, DefaultLifetime);

        Assert.Throws<InvalidOperationException>(() =>
            token.Rotate(ValidHash1, DateTime.UtcNow));
    }

    [Fact]
    public void Rotate_WhenAlreadyRotated_ThrowsInvalidOperationException()
    {
        var now = DateTime.UtcNow;
        var token = RefreshToken.Create(ValidSessionId, ValidHash1, now, DefaultLifetime);
        token.Rotate(ValidHash2, now);

        const string thirdHash = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a";
        Assert.Throws<InvalidOperationException>(() =>
            token.Rotate(thirdHash, now));
    }

    [Fact]
    public void ReplayInvariants_RotatedTokenRemainsIdentifiableAsReplayEvenAfterExpiry()
    {
        var now = DateTime.UtcNow;
        var token = RefreshToken.Create(ValidSessionId, ValidHash1, now, TimeSpan.FromMinutes(5));

        // Rotate the token
        token.Rotate(ValidHash2, now.AddMinutes(1));
        Assert.True(token.IsReplay);

        // Advance time well past original token expiration
        var pastExpiryTime = now.AddDays(10);
        Assert.True(token.IsExpired(pastExpiryTime));

        // The token MUST still remain classified as a replay!
        Assert.True(token.IsReplay);
        Assert.True(token.IsRotated);
    }

    [Fact]
    public void ReplayInvariants_NormalRevocationWithoutRotationIsNotClassifiedAsReplay()
    {
        var now = DateTime.UtcNow;
        var token = RefreshToken.Create(ValidSessionId, ValidHash1, now, DefaultLifetime);

        var newlyRevoked = token.Revoke(now);

        Assert.True(newlyRevoked);
        Assert.True(token.IsRevoked);
        Assert.False(token.IsRotated);
        Assert.Null(token.ReplacedByTokenHash);

        // Normal revocation without successor hash must NOT be classified as replay attack!
        Assert.False(token.IsReplay);
        Assert.False(token.IsActive(now));
    }

    [Fact]
    public void Revoke_WhenAlreadyRevoked_IsIdempotentAndReturnsFalse()
    {
        var now = DateTime.UtcNow;
        var token = RefreshToken.Create(ValidSessionId, ValidHash1, now, DefaultLifetime);

        var firstRevoke = token.Revoke(now);
        var secondRevoke = token.Revoke(now.AddMinutes(5));

        Assert.True(firstRevoke);
        Assert.False(secondRevoke);
        Assert.Equal(now, token.RevokedAtUtc);
    }

    [Fact]
    public void ToString_StrictlyOmitsTokenHashAndReplacedByTokenHash()
    {
        var token = RefreshToken.Create(ValidSessionId, ValidHash1, DateTime.UtcNow, DefaultLifetime);
        token.Rotate(ValidHash2, DateTime.UtcNow);

        var repr = token.ToString();

        Assert.Contains(token.Id.ToString(), repr);
        Assert.Contains(ValidSessionId.ToString(), repr);
        Assert.DoesNotContain(ValidHash1, repr);
        Assert.DoesNotContain(ValidHash2, repr);
    }
}
