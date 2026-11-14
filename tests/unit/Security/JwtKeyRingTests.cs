namespace MaintenX.UnitTests.Security;

using System.Security.Cryptography;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

public class JwtKeyRingTests
{
    private static string GenerateBase64Key(int byteCount = 32)
    {
        var bytes = new byte[byteCount];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }

    [Fact]
    public void KeyRing_InitializesActiveKeyAndCredentials()
    {
        var activeKid = "maintenx-active-key-v1";
        var activeSecret = GenerateBase64Key(32);

        var options = Options.Create(new JwtOptions
        {
            KeyId = activeKid,
            SigningKey = activeSecret
        });

        var ring = new JwtKeyRing(options);

        Assert.Equal(activeKid, ring.ActiveKeyId);
        Assert.NotNull(ring.ActiveSigningKey);
        Assert.Equal(activeKid, ring.ActiveSigningKey.KeyId);

        var creds = ring.CreateSigningCredentials();
        Assert.Equal(SecurityAlgorithms.HmacSha256, creds.Algorithm);
        Assert.Equal(activeKid, creds.Key.KeyId);
    }

    [Fact]
    public void KeyRing_ResolvesActiveKey_AndRetiredKeys()
    {
        var activeKid = "key-v2";
        var retiredKid1 = "key-v1";
        var retiredKid2 = "key-v0";

        var options = Options.Create(new JwtOptions
        {
            KeyId = activeKid,
            SigningKey = GenerateBase64Key(32),
            VerificationKeys = new Dictionary<string, string>
            {
                [retiredKid1] = GenerateBase64Key(32),
                [retiredKid2] = GenerateBase64Key(32)
            }
        });

        var ring = new JwtKeyRing(options);

        // Active key
        Assert.True(ring.TryGetKey(activeKid, out var activeKey));
        Assert.NotNull(activeKey);
        Assert.Equal(activeKid, activeKey.KeyId);

        // Retired keys
        Assert.True(ring.TryGetKey(retiredKid1, out var retKey1));
        Assert.NotNull(retKey1);
        Assert.Equal(retiredKid1, retKey1.KeyId);

        Assert.True(ring.TryGetKey(retiredKid2, out var retKey2));
        Assert.NotNull(retKey2);
        Assert.Equal(retiredKid2, retKey2.KeyId);

        // All keys count
        Assert.Equal(3, ring.GetAllKeys().Count());
    }

    [Theory]
    [InlineData("unknown-key-id")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void KeyRing_RejectsUnknownOrWhitespaceKeyId(string? unknownKid)
    {
        var options = Options.Create(new JwtOptions
        {
            KeyId = "active-key",
            SigningKey = GenerateBase64Key(32)
        });

        var ring = new JwtKeyRing(options);

        var found = ring.TryGetKey(unknownKid, out var key);

        Assert.False(found);
        Assert.Null(key);
    }
}

