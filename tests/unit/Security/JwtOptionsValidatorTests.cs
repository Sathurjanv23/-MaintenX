namespace MaintenX.UnitTests.Security;

using System.Security.Cryptography;
using MaintenX.Api.Configuration;
using Xunit;

public class JwtOptionsValidatorTests
{
    private readonly JwtOptionsValidator _validator = new();

    private static string GenerateBase64Key(int byteCount = 32)
    {
        var bytes = new byte[byteCount];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }

    [Fact]
    public void Validate_WithValidConfiguration_Succeeds()
    {
        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "active-key-1",
            SigningKey = GenerateBase64Key(32),
            AccessTokenLifetimeMinutes = 15
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithMissingIssuer_Fails(string? issuer)
    {
        var options = new JwtOptions
        {
            Issuer = issuer!,
            Audience = "https://maintenx.internal",
            KeyId = "active-key-1",
            SigningKey = GenerateBase64Key(32)
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Jwt:Issuer"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithMissingAudience_Fails(string? audience)
    {
        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = audience!,
            KeyId = "active-key-1",
            SigningKey = GenerateBase64Key(32)
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Jwt:Audience"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithMissingKeyId_Fails(string? keyId)
    {
        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = keyId!,
            SigningKey = GenerateBase64Key(32)
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Jwt:KeyId"));
    }

    [Fact]
    public void Validate_WithInvalidBase64SigningKey_Fails()
    {
        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "active-key-1",
            SigningKey = "Not-A-Valid-Base64-String!!!"
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Base64"));
    }

    [Fact]
    public void Validate_WithSigningKeyBelow256Bits_Fails()
    {
        // 16 bytes = 128 bits (below 256 bits threshold)
        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "active-key-1",
            SigningKey = GenerateBase64Key(16)
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Insufficient key entropy"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void Validate_WithZeroOrNegativeLifetime_Fails(int lifetimeMinutes)
    {
        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "active-key-1",
            SigningKey = GenerateBase64Key(32),
            AccessTokenLifetimeMinutes = lifetimeMinutes
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Lifetime must be greater than zero", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validate_WithVerificationKeyUnder256Bits_Fails()
    {
        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "active-key-1",
            SigningKey = GenerateBase64Key(32),
            VerificationKeys = new Dictionary<string, string>
            {
                ["retired-key-1"] = GenerateBase64Key(16) // Only 128 bits
            }
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("retired-key-1", StringComparison.OrdinalIgnoreCase) && f.Contains("insufficient entropy", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validate_WithConflictingActiveKeyIdInVerificationRing_Fails()
    {
        var activeKey = GenerateBase64Key(32);
        var conflictingKey = GenerateBase64Key(32);

        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "active-key-1",
            SigningKey = activeKey,
            VerificationKeys = new Dictionary<string, string>
            {
                ["active-key-1"] = conflictingKey // Same ID, different key material
            }
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("conflicting key material"));
    }

    [Fact]
    public void Validate_ToString_NeverOutputsRawKeyMaterial()
    {
        var secret = GenerateBase64Key(32);
        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "active-key-1",
            SigningKey = secret
        };

        var stringRep = options.ToString();

        Assert.DoesNotContain(secret, stringRep);
        Assert.Contains("active-key-1", stringRep);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-24)]
    public void Validate_WithZeroOrNegativeRetiredKeyRetentionHours_Fails(int hours)
    {
        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "active-key-1",
            SigningKey = GenerateBase64Key(32),
            RetiredKeyRetentionHours = hours
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("retired key retention hours", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validate_WithDevelopmentPlaceholderKey_SatisfiesAllValidationRules()
    {
        const string devPlaceholderKey = "REVWX09OTFlfSU5TRUNVUkVfS0VZXzMyX0JZVEVTISE=";
        var decoded = Convert.FromBase64String(devPlaceholderKey);
        Assert.Equal(32, decoded.Length);

        var options = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "dev-key-2026-v1",
            SigningKey = devPlaceholderKey,
            AccessTokenLifetimeMinutes = 15,
            RetiredKeyRetentionHours = 24
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }
}

