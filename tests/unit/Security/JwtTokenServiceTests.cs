namespace MaintenX.UnitTests.Security;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Configuration;
using MaintenX.Api.Domain.Auth;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

public class JwtTokenServiceTests
{
    private const string TestKeyId = "test-key-2026-v1";
    private const string TestIssuer = "https://api.maintenx.internal";
    private const string TestAudience = "https://maintenx.internal";
    private static readonly string SigningKeyBase64 = GenerateBase64Key(32);

    private readonly JwtKeyRing _keyRing;
    private readonly IOptions<JwtOptions> _jwtOptions;
    private readonly JwtTokenService _sut;
    private readonly JwtSecurityTokenHandler _tokenHandler;

    private static string GenerateBase64Key(int byteCount = 32)
    {
        var bytes = new byte[byteCount];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }

    public JwtTokenServiceTests()
    {
        var options = new JwtOptions
        {
            Issuer = TestIssuer,
            Audience = TestAudience,
            KeyId = TestKeyId,
            SigningKey = SigningKeyBase64,
            AccessTokenLifetimeMinutes = 15,
            RetiredKeyRetentionHours = 24
        };

        _jwtOptions = Options.Create(options);
        _keyRing = new JwtKeyRing(_jwtOptions);
        _sut = new JwtTokenService(_keyRing, _jwtOptions);
        _tokenHandler = new JwtSecurityTokenHandler();
    }

    [Fact]
    public void GenerateAccessToken_IssuesValidJwt_With15MinuteLifetime()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var securityStamp = "sec-stamp-12345";
        var before = DateTime.UtcNow;

        var result = _sut.GenerateAccessToken(userId, sessionId, securityStamp);

        var after = DateTime.UtcNow;

        Assert.NotNull(result);
        Assert.False(string.IsNullOrWhiteSpace(result.Token));
        Assert.False(string.IsNullOrWhiteSpace(result.Jti));

        // Verify lifetime is approximately 15 minutes from now
        var expectedExpiry = before.AddMinutes(15);
        Assert.True(result.ExpiresAtUtc >= before.AddMinutes(14.9));
        Assert.True(result.ExpiresAtUtc <= after.AddMinutes(15.1));
    }

    [Fact]
    public void GenerateAccessToken_IncludesRequiredClaims_Sub_Sid_Sst_Jti()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var securityStamp = "sec-stamp-abcdef";

        var result = _sut.GenerateAccessToken(userId, sessionId, securityStamp);

        var token = _tokenHandler.ReadJwtToken(result.Token);

        Assert.Equal(userId.ToString("D"), token.Subject);
        Assert.Equal(sessionId.ToString("D"), token.Claims.First(c => c.Type == "sid").Value);
        Assert.Equal(securityStamp, token.Claims.First(c => c.Type == "sst").Value);
        Assert.Equal(result.Jti, token.Id);
    }

    [Fact]
    public void GenerateAccessToken_SetsCorrectKidAndAlgorithmInHeader()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var securityStamp = "sec-stamp-headers";

        var result = _sut.GenerateAccessToken(userId, sessionId, securityStamp);

        var token = _tokenHandler.ReadJwtToken(result.Token);

        Assert.Equal(TestKeyId, token.Header.Kid);
        Assert.Equal(SecurityAlgorithms.HmacSha256, token.Header.Alg);
    }

    [Fact]
    public void GenerateAccessToken_EnforcesIssuerAndAudience()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var securityStamp = "sec-stamp-aud";

        var result = _sut.GenerateAccessToken(userId, sessionId, securityStamp);

        var token = _tokenHandler.ReadJwtToken(result.Token);

        Assert.Equal(TestIssuer, token.Issuer);
        Assert.Contains(TestAudience, token.Audiences);
    }

    [Fact]
    public void GenerateAccessToken_ValidatesSuccessfullyAgainstKeyRing()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var securityStamp = "sec-stamp-signature";

        var result = _sut.GenerateAccessToken(userId, sessionId, securityStamp);

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = TestIssuer,
            ValidateAudience = true,
            ValidAudience = TestAudience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            IssuerSigningKeyResolver = (_, _, kid, _) =>
            {
                if (_keyRing.TryGetKey(kid, out var key))
                {
                    return [key!];
                }
                return [];
            }
        };

        var principal = _tokenHandler.ValidateToken(result.Token, validationParams, out var validatedToken);

        Assert.NotNull(principal);
        Assert.NotNull(validatedToken);
        Assert.Equal(userId.ToString("D"), principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? principal.FindFirst("sub")?.Value);
    }

    [Fact]
    public void GenerateAccessToken_FromEntities_MatchesEntityIdentifiers()
    {
        var user = User.Create("user@example.com", "hash-pw");
        var session = UserSession.Create(user.Id, DateTime.UtcNow, TimeSpan.FromDays(7));

        var result = _sut.GenerateAccessToken(user, session);

        var token = _tokenHandler.ReadJwtToken(result.Token);

        Assert.Equal(user.Id.ToString("D"), token.Subject);
        Assert.Equal(session.Id.ToString("D"), token.Claims.First(c => c.Type == "sid").Value);
        Assert.Equal(user.SecurityStamp, token.Claims.First(c => c.Type == "sst").Value);
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111", "stamp")]
    [InlineData("11111111-1111-1111-1111-111111111111", "00000000-0000-0000-0000-000000000000", "stamp")]
    public void GenerateAccessToken_WithEmptyGuid_ThrowsArgumentException(string userGuidStr, string sessionGuidStr, string stamp)
    {
        var uId = Guid.Parse(userGuidStr);
        var sId = Guid.Parse(sessionGuidStr);

        Assert.Throws<ArgumentException>(() => _sut.GenerateAccessToken(uId, sId, stamp));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void GenerateAccessToken_WithInvalidSecurityStamp_ThrowsArgumentException(string? invalidStamp)
    {
        var uId = Guid.NewGuid();
        var sId = Guid.NewGuid();

        Assert.ThrowsAny<ArgumentException>(() => _sut.GenerateAccessToken(uId, sId, invalidStamp!));
    }

    [Fact]
    public void AccessTokenResult_ToString_RedactsRawToken()
    {
        var result = _sut.GenerateAccessToken(Guid.NewGuid(), Guid.NewGuid(), "stamp-test");
        var str = result.ToString();

        Assert.DoesNotContain(result.Token, str);
        Assert.Contains("[REDACTED]", str);
        Assert.Contains(result.Jti, str);
    }
}
