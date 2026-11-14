namespace MaintenX.UnitTests.Domain.Auth;

using System.Collections.Frozen;
using System.Reflection;
using MaintenX.Api.Domain.Auth;
using Xunit;

public class SecurityAuditEventTests
{
    private static readonly Guid ValidUserId = Guid.NewGuid();
    private static readonly Guid ValidSessionId = Guid.NewGuid();

    [Fact]
    public void Create_WithValidApprovedParameters_InitializesEventCorrectly()
    {
        var now = DateTime.UtcNow;
        const string clientIp = "192.168.1.100";
        var meta = SecurityAuditMetadata.Create(
            reason: SecurityAuditMetadata.Reasons.InvalidCredentials,
            detectedLineage: SecurityAuditMetadata.Lineages.PredecessorRotated,
            actionTaken: SecurityAuditMetadata.Actions.LockoutApplied);

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
        Assert.Equal(SecurityAuditMetadata.Reasons.InvalidCredentials, evt.Reason);
        Assert.Equal(SecurityAuditMetadata.Lineages.PredecessorRotated, evt.DetectedLineage);
        Assert.Equal(SecurityAuditMetadata.Actions.LockoutApplied, evt.ActionTaken);
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
            reason: SecurityAuditMetadata.Reasons.TokenReplay,
            detectedLineage: "ancestor_v1",
            actionTaken: SecurityAuditMetadata.Actions.SessionRevoked);

        Assert.Equal(SecurityAuditMetadata.Reasons.TokenReplay, evt.Reason);
        Assert.Equal("ancestor_v1", evt.DetectedLineage);
        Assert.Equal(SecurityAuditMetadata.Actions.SessionRevoked, evt.ActionTaken);
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
    [InlineData(SecurityAuditMetadata.Reasons.StandardLogin)]
    [InlineData(SecurityAuditMetadata.Reasons.InvalidCredentials)]
    [InlineData(SecurityAuditMetadata.Reasons.AccountLocked)]
    [InlineData(SecurityAuditMetadata.Reasons.TokenReplay)]
    [InlineData(SecurityAuditMetadata.Reasons.UserLogout)]
    [InlineData(SecurityAuditMetadata.Reasons.PasswordChanged)]
    public void Metadata_WithApprovedReasons_Succeeds(string approvedReason)
    {
        var meta = SecurityAuditMetadata.Create(reason: approvedReason);
        Assert.Equal(approvedReason, meta.Reason);
    }

    [Theory]
    [InlineData(SecurityAuditMetadata.Actions.Permit)]
    [InlineData(SecurityAuditMetadata.Actions.Deny)]
    [InlineData(SecurityAuditMetadata.Actions.LockoutApplied)]
    [InlineData(SecurityAuditMetadata.Actions.SessionRevoked)]
    [InlineData(SecurityAuditMetadata.Actions.TokenRotated)]
    public void Metadata_WithApprovedActions_Succeeds(string approvedAction)
    {
        var meta = SecurityAuditMetadata.Create(actionTaken: approvedAction);
        Assert.Equal(approvedAction, meta.ActionTaken);
    }

    [Theory]
    [InlineData(SecurityAuditMetadata.Lineages.RootSession)]
    [InlineData(SecurityAuditMetadata.Lineages.PredecessorRotated)]
    [InlineData("lineage_1")]
    [InlineData("ancestor_v1")]
    [InlineData("generation_2")]
    [InlineData("depth_3")]
    public void Metadata_WithApprovedOrConstrainedLineages_Succeeds(string validLineage)
    {
        var meta = SecurityAuditMetadata.Create(detectedLineage: validLineage);
        Assert.Equal(validLineage, meta.DetectedLineage);
    }

    [Theory]
    [InlineData("arbitrary free form text")]
    [InlineData("user entered wrong password")]
    [InlineData("valid_reason")]
    [InlineData("something_custom")]
    [InlineData("user@example.com")]
    [InlineData("+1-800-555-0199")]
    [InlineData("0771234567")]
    [InlineData("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M")]
    [InlineData("Bearer secrettoken123")]
    [InlineData("$argon2id$v=19$m=65536,t=3,p=4$somehash")]
    public void Metadata_WithUnapprovedReason_ThrowsArgumentException(string unapprovedReason)
    {
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditMetadata.Create(reason: unapprovedReason));

        Assert.Throws<ArgumentException>(() =>
            new SecurityAuditMetadata(reason: unapprovedReason));
    }

    [Theory]
    [InlineData("arbitrary action text")]
    [InlineData("custom_action")]
    [InlineData("user@example.com")]
    [InlineData("+1-555-0199")]
    [InlineData("eyJhbGciOiJIUzI1Ni...")]
    [InlineData("password123")]
    public void Metadata_WithUnapprovedAction_ThrowsArgumentException(string unapprovedAction)
    {
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditMetadata.Create(actionTaken: unapprovedAction));

        Assert.Throws<ArgumentException>(() =>
            new SecurityAuditMetadata(actionTaken: unapprovedAction));
    }

    [Theory]
    [InlineData("unapproved_lineage")]
    [InlineData("user@example.com")]
    [InlineData("+1-800-555-0199")]
    [InlineData("eyJhbGciOi...")]
    [InlineData("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("bad/format")]
    [InlineData("lineage with spaces")]
    public void Metadata_WithUnapprovedLineage_ThrowsArgumentException(string unapprovedLineage)
    {
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditMetadata.Create(detectedLineage: unapprovedLineage));

        Assert.Throws<ArgumentException>(() =>
            new SecurityAuditMetadata(detectedLineage: unapprovedLineage));
    }

    [Fact]
    public void Metadata_DirectConstructorAndFactory_EnforceIdenticalValidation()
    {
        // Both reject unapproved values identically
        Assert.Throws<ArgumentException>(() =>
            new SecurityAuditMetadata(reason: "unapproved"));
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditMetadata.Create(reason: "unapproved"));

        // Both construct identical valid objects
        var fromCtor = new SecurityAuditMetadata(
            SecurityAuditMetadata.Reasons.StandardLogin,
            "lineage_1",
            SecurityAuditMetadata.Actions.Permit);

        var fromFactory = SecurityAuditMetadata.Create(
            SecurityAuditMetadata.Reasons.StandardLogin,
            "lineage_1",
            SecurityAuditMetadata.Actions.Permit);

        Assert.Equal(fromCtor, fromFactory);
        Assert.True(fromCtor == fromFactory);
    }

    [Fact]
    public void Metadata_HasNoPublicParameterlessConstructor()
    {
        var publicConstructors = typeof(SecurityAuditMetadata).GetConstructors(BindingFlags.Public | BindingFlags.Instance);
        Assert.DoesNotContain(publicConstructors, ctor => ctor.GetParameters().Length == 0);

        // Confirm non-public parameterless constructor exists for EF Core materialization
        var nonPublicParameterlessCtor = typeof(SecurityAuditMetadata).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            null,
            Type.EmptyTypes,
            null);
        Assert.NotNull(nonPublicParameterlessCtor);
    }

    [Fact]
    public void Metadata_PropertiesMustNotHavePublicSetters()
    {
        var properties = typeof(SecurityAuditMetadata).GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Assert.NotEmpty(properties);

        foreach (var prop in properties)
        {
            var setMethod = prop.GetSetMethod(nonPublic: false);
            Assert.True(
                setMethod == null,
                $"Property '{prop.Name}' on '{nameof(SecurityAuditMetadata)}' must not have a public setter.");
        }
    }

    [Fact]
    public void Metadata_AllowLists_AreGenuinelyImmutableFrozenSets()
    {
        Assert.IsAssignableFrom<FrozenSet<string>>(SecurityAuditMetadata.ApprovedReasons);
        Assert.IsAssignableFrom<FrozenSet<string>>(SecurityAuditMetadata.ApprovedActions);
        Assert.IsAssignableFrom<FrozenSet<string>>(SecurityAuditMetadata.ApprovedLineages);

        // Casting to mutable HashSet throws InvalidCastException
        Assert.Throws<InvalidCastException>(() =>
            (HashSet<string>)(object)SecurityAuditMetadata.ApprovedReasons);

        // Cannot add via ICollection
        var col = (ICollection<string>)SecurityAuditMetadata.ApprovedReasons;
        Assert.True(col.IsReadOnly);
        Assert.Throws<NotSupportedException>(() => col.Add("injected_reason"));
    }

    [Fact]
    public void Metadata_ValueEquality_BehavesCorrectly()
    {
        var m1 = SecurityAuditMetadata.Create(
            SecurityAuditMetadata.Reasons.StandardLogin,
            SecurityAuditMetadata.Lineages.PredecessorRotated,
            SecurityAuditMetadata.Actions.Permit);

        var m2 = new SecurityAuditMetadata(
            SecurityAuditMetadata.Reasons.StandardLogin,
            SecurityAuditMetadata.Lineages.PredecessorRotated,
            SecurityAuditMetadata.Actions.Permit);

        var m3 = SecurityAuditMetadata.Create(
            SecurityAuditMetadata.Reasons.InvalidCredentials,
            SecurityAuditMetadata.Lineages.PredecessorRotated,
            SecurityAuditMetadata.Actions.Deny);

        Assert.Equal(m1, m2);
        Assert.True(m1 == m2);
        Assert.NotEqual(m1, m3);
        Assert.True(m1 != m3);
        Assert.Equal(m1.GetHashCode(), m2.GetHashCode());
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
            reason: SecurityAuditMetadata.Reasons.StandardLogin,
            detectedLineage: null,
            actionTaken: SecurityAuditMetadata.Actions.Permit);

        var repr = evt.ToString();

        Assert.Contains(evt.Id.ToString(), repr);
        Assert.Contains(nameof(SecurityAuditEventType.LoginSuccess), repr);
        Assert.Contains(ValidUserId.ToString(), repr);
        Assert.Contains(ValidSessionId.ToString(), repr);
        Assert.Contains("10.0.0.1", repr);
        Assert.Contains(SecurityAuditMetadata.Reasons.StandardLogin, repr);
    }
}
