namespace MaintenX.UnitTests.Domain.Auth;

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
        const string safeDetails = "{\"action\":\"login\",\"browser\":\"Chrome\"}";
        const string clientIp = "192.168.1.100";

        var evt = SecurityAuditEvent.Create(
            SecurityAuditEventType.LoginSuccess,
            now,
            ValidUserId,
            ValidSessionId,
            clientIp,
            safeDetails);

        Assert.NotEqual(Guid.Empty, evt.Id);
        Assert.Equal(SecurityAuditEventType.LoginSuccess, evt.EventType);
        Assert.Equal(ValidUserId, evt.UserId);
        Assert.Equal(ValidSessionId, evt.SessionId);
        Assert.Equal(clientIp, evt.ClientIp);
        Assert.Equal(safeDetails, evt.Details);
        Assert.Equal(now, evt.CreatedAtUtc);
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

    [Fact]
    public void Create_WithClientIpExceeding45Characters_TruncatesSafely()
    {
        var longIp = new string('1', 50);
        var evt = SecurityAuditEvent.Create(
            SecurityAuditEventType.LoginFailed,
            DateTime.UtcNow,
            clientIp: longIp);

        Assert.NotNull(evt.ClientIp);
        Assert.Equal(45, evt.ClientIp.Length);
        Assert.Equal(longIp[..45], evt.ClientIp);
    }

    [Theory]
    [InlineData("User entered password: Secret123")]
    [InlineData("client sent secret in body")]
    [InlineData("Authorization: Bearer eyJhbGciOi...")]
    [InlineData("raw token=abcd1234efgh")]
    [InlineData("current SecurityStamp was 12345")]
    [InlineData("password hash is $argon2id$v=19...")]
    public void Create_WithProhibitedSensitiveKeywordsInDetails_ThrowsArgumentException(string sensitiveDetails)
    {
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditEvent.Create(
                SecurityAuditEventType.LoginFailed,
                DateTime.UtcNow,
                details: sensitiveDetails));
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
            "{\"context\":\"safe_audit_info\"}");

        var repr = evt.ToString();

        Assert.Contains(evt.Id.ToString(), repr);
        Assert.Contains(nameof(SecurityAuditEventType.LoginSuccess), repr);
        Assert.Contains(ValidUserId.ToString(), repr);
        Assert.Contains(ValidSessionId.ToString(), repr);
        Assert.Contains("10.0.0.1", repr);
        Assert.DoesNotContain("safe_audit_info", repr);
    }
}
