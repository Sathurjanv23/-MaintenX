namespace MaintenX.UnitTests.Domain.Auth;

using System.Reflection;
using MaintenX.Api.Domain.Auth;
using Xunit;

public class SecurityAuditEventTests
{
    private static readonly Guid ValidUserId = Guid.NewGuid();
    private static readonly Guid ValidSessionId = Guid.NewGuid();

    [Fact]
    public void Create_WithValidParameters_InitializesEventCorrectly()
    {
        var now = DateTime.UtcNow;
        const string clientIp = "192.168.1.100";
        var meta = SecurityAuditMetadata.Create(
            reason: "invalid_credentials",
            detectedLineage: "predecessor_rotated",
            actionTaken: "lockout_applied");

        var evt = SecurityAuditEvent.Create(
            SecurityAuditEventType.LoginFailed,
            now,
            ValidUserId,
            ValidSessionId,
            clientIp,
            meta);

        Assert.NotEqual(Guid.Empty, evt.Id);
        Assert.Equal(SecurityAuditEventType.LoginFailed, evt.EventType);
        Assert.Equal(ValidUserId, evt.UserId);
        Assert.Equal(ValidSessionId, evt.SessionId);
        Assert.Equal(clientIp, evt.ClientIp);
        Assert.NotNull(evt.Metadata);
        Assert.Equal("invalid_credentials", evt.Reason);
        Assert.Equal("predecessor_rotated", evt.DetectedLineage);
        Assert.Equal("lockout_applied", evt.ActionTaken);
        Assert.Equal(now, evt.CreatedAtUtc);
    }

    [Fact]
    public void Create_WithConvenienceMetadataParameters_InitializesCorrectly()
    {
        var now = DateTime.UtcNow;
        var evt = SecurityAuditEvent.Create(
            SecurityAuditEventType.TokenReplayDetected,
            now,
            ValidUserId,
            ValidSessionId,
            "10.0.0.1",
            reason: "token_replay",
            detectedLineage: "ancestor_v1",
            actionTaken: "session_revoked");

        Assert.Equal("token_replay", evt.Reason);
        Assert.Equal("ancestor_v1", evt.DetectedLineage);
        Assert.Equal("session_revoked", evt.ActionTaken);
    }

    [Fact]
    public void Create_WithEmptyGuids_NormalizesToNull()
    {
        var now = DateTime.UtcNow;
        var evt = SecurityAuditEvent.Create(
            SecurityAuditEventType.LoginFailed,
            now,
            Guid.Empty,
            Guid.Empty);

        Assert.Null(evt.UserId);
        Assert.Null(evt.SessionId);
    }

    [Theory]
    [InlineData("192.168.1.1", "192.168.1.1")]
    [InlineData("10.0.0.254", "10.0.0.254")]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("::1", "::1")]
    [InlineData("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334")]
    public void ValidateAndNormalizeClientIp_WithValidIps_NormalizesCorrectly(string raw, string expected)
    {
        var normalized = SecurityAuditEvent.ValidateAndNormalizeClientIp(raw);
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateAndNormalizeClientIp_WithNullOrWhitespace_ReturnsNull(string? raw)
    {
        var normalized = SecurityAuditEvent.ValidateAndNormalizeClientIp(raw);
        Assert.Null(normalized);
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("999.999.999.999")]
    [InlineData("1.2.3.4.5")]
    [InlineData("192.168.1.1/24")]
    [InlineData("11111111111111111111111111111111111111111111111111")]
    public void ValidateAndNormalizeClientIp_WithInvalidIp_ThrowsArgumentException(string invalidIp)
    {
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditEvent.ValidateAndNormalizeClientIp(invalidIp));
    }

    [Theory]
    [InlineData("user@example.com")]
    [InlineData("admin@maintenx.internal")]
    [InlineData("login attempt for bob@test.com")]
    public void Metadata_WithEmailAddress_ThrowsArgumentException(string valueWithEmail)
    {
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditMetadata.Create(reason: valueWithEmail));
    }

    [Theory]
    [InlineData("$argon2id$v=19$m=65536,t=3,p=4$somehash")]
    [InlineData("$pbkdf2-sha256$29000$test")]
    [InlineData("$2a$12$abcdefghijklmnopqrstuv")]
    public void Metadata_WithPasswordHash_ThrowsArgumentException(string valueWithHash)
    {
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditMetadata.Create(reason: valueWithHash));
    }

    [Fact]
    public void Metadata_WithRaw64CharHexTokenHash_ThrowsArgumentException()
    {
        const string raw64CharHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditMetadata.Create(detectedLineage: raw64CharHash));
    }

    [Theory]
    [InlineData("User entered password: wrong")]
    [InlineData("client sent secret in body")]
    [InlineData("Authorization: Bearer eyJhbGciOi...")]
    [InlineData("current SecurityStamp was 12345")]
    public void Metadata_WithProhibitedSensitiveKeywords_ThrowsArgumentException(string sensitiveValue)
    {
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditMetadata.Create(actionTaken: sensitiveValue));
    }

    [Fact]
    public void Metadata_Exceeding200Characters_ThrowsArgumentException()
    {
        var longValue = new string('a', 201);
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditMetadata.Create(reason: longValue));
    }

    [Fact]
    public void DomainInvariants_SecurityAuditEventPropertiesMustNotHavePublicSetters()
    {
        var properties = typeof(SecurityAuditEvent).GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Assert.NotEmpty(properties);

        foreach (var prop in properties)
        {
            var setMethod = prop.GetSetMethod(nonPublic: false);
            Assert.True(
                setMethod == null,
                $"Property '{prop.Name}' on '{nameof(SecurityAuditEvent)}' must not have a public setter.");
        }
    }

    [Fact]
    public void ToString_ReturnsSanitizedSummaryOmittingDetailsPayload()
    {
        var evt = SecurityAuditEvent.Create(
            SecurityAuditEventType.LoginSuccess,
            DateTime.UtcNow,
            ValidUserId,
            ValidSessionId,
            "10.0.0.1",
            reason: "standard_login",
            detectedLineage: null,
            actionTaken: "permit");

        var repr = evt.ToString();

        Assert.Contains(evt.Id.ToString(), repr);
        Assert.Contains(nameof(SecurityAuditEventType.LoginSuccess), repr);
        Assert.Contains(ValidUserId.ToString(), repr);
        Assert.Contains(ValidSessionId.ToString(), repr);
        Assert.Contains("10.0.0.1", repr);
        Assert.Contains("standard_login", repr);
    }
}
