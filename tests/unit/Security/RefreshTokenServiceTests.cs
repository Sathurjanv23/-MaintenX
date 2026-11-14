namespace MaintenX.UnitTests.Security;

using System.Buffers.Text;
using System.Text.RegularExpressions;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Auth;
using Xunit;

public class RefreshTokenServiceTests
{
    private readonly RefreshTokenService _sut;
    private static readonly Regex Sha256HexRegex = new(@"^[a-f0-9]{64}$", RegexOptions.Compiled);

    public RefreshTokenServiceTests()
    {
        _sut = new RefreshTokenService();
    }

    [Fact]
    public void GenerateToken_Produces64ByteRandomTokenAndSha256Digest()
    {
        var result = _sut.GenerateToken();

        Assert.NotNull(result);
        Assert.False(string.IsNullOrWhiteSpace(result.RawToken));
        Assert.False(string.IsNullOrWhiteSpace(result.TokenHash));

        // Raw token decoded from Base64Url should be exactly 64 bytes
        var decodedBytes = Base64Url.DecodeFromChars(result.RawToken);
        Assert.Equal(64, decodedBytes.Length);

        // TokenHash must be 64-char lowercase hex
        Assert.Equal(64, result.TokenHash.Length);
        Assert.Matches(Sha256HexRegex, result.TokenHash);
        Assert.Equal(result.TokenHash.ToLowerInvariant(), result.TokenHash);

        // Verify hash of raw token matches token hash
        Assert.Equal(_sut.HashToken(result.RawToken), result.TokenHash);
    }

    [Fact]
    public void GenerateToken_ConsecutiveCalls_ProduceDistinctTokens()
    {
        var token1 = _sut.GenerateToken();
        var token2 = _sut.GenerateToken();

        Assert.NotEqual(token1.RawToken, token2.RawToken);
        Assert.NotEqual(token1.TokenHash, token2.TokenHash);
    }

    [Fact]
    public void HashToken_IsDeterministic()
    {
        var rawToken = "dGVzdC1yYXctdG9rZW4tc3RyaW5nLWZvci1kZXRlcm1pbmlzdGljLWhhc2hpbmctZXhhbXBsZQ";

        var hash1 = _sut.HashToken(rawToken);
        var hash2 = _sut.HashToken(rawToken);

        Assert.Equal(hash1, hash2);
        Assert.Equal(64, hash1.Length);
        Assert.Matches(Sha256HexRegex, hash1);
    }

    [Fact]
    public void HashToken_ProducesDigest_PassingDomainEntityValidation()
    {
        var generated = _sut.GenerateToken();

        // Validating with domain entity static method must succeed without throwing
        var normalized = RefreshToken.ValidateAndNormalizeHash(generated.TokenHash);
        Assert.Equal(generated.TokenHash, normalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void HashToken_WithInvalidInput_ThrowsArgumentException(string? invalidRawToken)
    {
        Assert.ThrowsAny<ArgumentException>(() => _sut.HashToken(invalidRawToken!));
    }

    [Fact]
    public void CreateRefreshTokenEntity_WithSession_CapsAtSessionBoundary()
    {
        var now = DateTime.UtcNow;
        var userId = Guid.NewGuid();
        // Session expires in 3 days (shorter than 7-day nominal token lifetime)
        var session = UserSession.Create(userId, now, TimeSpan.FromDays(3));
        var generated = _sut.GenerateToken();

        var entity = _sut.CreateRefreshTokenEntity(session, generated.TokenHash, now);

        Assert.Equal(session.Id, entity.SessionId);
        Assert.Equal(generated.TokenHash, entity.TokenHash);
        Assert.Equal(now, entity.CreatedAtUtc);
        // Expiry must be capped at 3 days (session expiry), not 7 days!
        Assert.Equal(session.ExpiresAtUtc, entity.ExpiresAtUtc);
    }

    [Fact]
    public void CreateRefreshTokenEntity_WithLongSession_UsesNominal7Days()
    {
        var now = DateTime.UtcNow;
        var userId = Guid.NewGuid();
        // Session expires in 30 days (longer than 7-day nominal token lifetime)
        var session = UserSession.Create(userId, now, TimeSpan.FromDays(30));
        var generated = _sut.GenerateToken();

        var entity = _sut.CreateRefreshTokenEntity(session, generated.TokenHash, now);

        Assert.Equal(session.Id, entity.SessionId);
        Assert.Equal(now.AddDays(7), entity.ExpiresAtUtc);
    }

    [Fact]
    public void GeneratedRefreshToken_ToString_StrictlyRedactsRawTokenAndHash()
    {
        var generated = _sut.GenerateToken();
        var str = generated.ToString();

        Assert.DoesNotContain(generated.RawToken, str);
        Assert.DoesNotContain(generated.TokenHash, str);
        Assert.Contains("[REDACTED]", str);
    }
}
