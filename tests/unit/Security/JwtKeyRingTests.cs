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

    [Fact]
    public void KeyRing_RetiredKey_BeforeRetentionBoundary_IsValidAndCannotBePurged()
    {
        var t0 = new DateTimeOffset(2026, 11, 14, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new TestTimeProvider(t0);

        var activeKid = "key-v2";
        var retiredKid = "key-v1";
        var retiredSecret = GenerateBase64Key(32);

        var options = Options.Create(new JwtOptions
        {
            KeyId = activeKid,
            SigningKey = GenerateBase64Key(32),
            RetiredKeyRetentionHours = 24,
            VerificationKeys = new Dictionary<string, string>
            {
                [retiredKid] = retiredSecret
            },
            RetiredAtTimestamps = new Dictionary<string, DateTimeOffset>
            {
                [retiredKid] = t0
            }
        });

        var ring = new JwtKeyRing(options, timeProvider);

        // 23 hours and 59 minutes after retirement: before 24h boundary
        timeProvider.SetUtcNow(t0.AddHours(23).AddMinutes(59));

        // 1. Key must remain resolvable for signature verification
        Assert.True(ring.TryGetKey(retiredKid, out var key));
        Assert.NotNull(key);
        Assert.Equal(retiredKid, key.KeyId);

        // 2. Key cannot be purged before 24 hours have elapsed
        Assert.False(ring.CanPurgeKey(retiredKid, out var remaining));
        Assert.True(remaining > TimeSpan.Zero);
        Assert.False(ring.TryPurgeRetiredKey(retiredKid, out var failureReason));
        Assert.Contains("mandatory 24-hour retention period has not elapsed", failureReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void KeyRing_RetiredKey_ExactlyAtRetentionBoundary_IsExpiredAndCanBePurged()
    {
        var t0 = new DateTimeOffset(2026, 11, 14, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new TestTimeProvider(t0);

        var activeKid = "key-v2";
        var retiredKid = "key-v1";
        var retiredSecret = GenerateBase64Key(32);

        var options = Options.Create(new JwtOptions
        {
            KeyId = activeKid,
            SigningKey = GenerateBase64Key(32),
            RetiredKeyRetentionHours = 24,
            VerificationKeys = new Dictionary<string, string>
            {
                [retiredKid] = retiredSecret
            },
            RetiredAtTimestamps = new Dictionary<string, DateTimeOffset>
            {
                [retiredKid] = t0
            }
        });

        var ring = new JwtKeyRing(options, timeProvider);

        // Exactly at the 24-hour retention boundary
        timeProvider.SetUtcNow(t0.AddHours(24));

        // 1. Exactly at boundary, elapsed retention equals 24 hours: key is considered expired for new verifications
        Assert.False(ring.TryGetKey(retiredKid, out _));

        // 2. Can now safely be purged from the key ring
        Assert.True(ring.CanPurgeKey(retiredKid, out var remaining));
        Assert.Equal(TimeSpan.Zero, remaining);
        Assert.True(ring.TryPurgeRetiredKey(retiredKid, out var failureReason));
        Assert.Null(failureReason);
    }

    [Fact]
    public void KeyRing_RetiredKey_AfterRetentionBoundary_IsExpiredAndPurgedKeyIsRejected()
    {
        var t0 = new DateTimeOffset(2026, 11, 14, 0, 0, 0, TimeSpan.Zero);
        var timeProvider = new TestTimeProvider(t0);

        var activeKid = "key-v2";
        var retiredKid = "key-v1";
        var retiredSecret = GenerateBase64Key(32);

        var options = Options.Create(new JwtOptions
        {
            KeyId = activeKid,
            SigningKey = GenerateBase64Key(32),
            RetiredKeyRetentionHours = 24,
            VerificationKeys = new Dictionary<string, string>
            {
                [retiredKid] = retiredSecret
            },
            RetiredAtTimestamps = new Dictionary<string, DateTimeOffset>
            {
                [retiredKid] = t0
            }
        });

        var ring = new JwtKeyRing(options, timeProvider);

        // 25 hours after retirement (well past boundary)
        timeProvider.SetUtcNow(t0.AddHours(25));

        // 1. Expired key is rejected by TryGetKey
        Assert.False(ring.TryGetKey(retiredKid, out var key));
        Assert.Null(key);

        // 2. Purge key permanently
        Assert.True(ring.TryPurgeRetiredKey(retiredKid, out _));

        // 3. Purged key is rejected
        Assert.False(ring.TryGetKey(retiredKid, out _));
    }

    [Fact]
    public void KeyRing_ActiveKey_CannotBeRetiredOrPurged()
    {
        var activeKid = "key-v1";
        var options = Options.Create(new JwtOptions
        {
            KeyId = activeKid,
            SigningKey = GenerateBase64Key(32)
        });

        var ring = new JwtKeyRing(options);

        // Cannot retire the active key while it is active
        Assert.Throws<InvalidOperationException>(() =>
        {
            ring.RetireKey(activeKid, GenerateBase64Key(32));
        });

        // Cannot purge the active key
        Assert.False(ring.TryPurgeRetiredKey(activeKid, out var failureReason));
        Assert.Contains("Cannot purge the active signing key", failureReason);
    }
}
