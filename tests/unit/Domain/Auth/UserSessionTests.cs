namespace MaintenX.UnitTests.Domain.Auth;

using MaintenX.Api.Domain.Auth;
using Xunit;

public class UserSessionTests
{
    private static readonly Guid ValidUserId = Guid.NewGuid();
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(8);

    [Fact]
    public void Create_WithValidParameters_InitializesSessionCorrectly()
    {
        var now = DateTime.UtcNow;
        var session = UserSession.Create(ValidUserId, now, DefaultLifetime);

        Assert.NotEqual(Guid.Empty, session.Id);
        Assert.Equal(ValidUserId, session.UserId);
        Assert.Equal(now, session.CreatedAtUtc);
        Assert.Equal(now.Add(DefaultLifetime), session.ExpiresAtUtc);
        Assert.Null(session.RevokedAtUtc);
        Assert.Null(session.RevocationReason);
        Assert.False(session.IsRevoked);
        Assert.True(session.IsActive(now));
        Assert.False(session.IsExpired(now));
        Assert.Equal(1, session.Version);
    }

    [Fact]
    public void Create_WithEmptyUserId_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            UserSession.Create(Guid.Empty, DateTime.UtcNow, DefaultLifetime));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-60)]
    public void Create_WithNonPositiveLifetime_ThrowsArgumentException(int seconds)
    {
        Assert.Throws<ArgumentException>(() =>
            UserSession.Create(ValidUserId, DateTime.UtcNow, TimeSpan.FromSeconds(seconds)));
    }

    [Fact]
    public void IsExpired_EvaluatesAccuratelyAgainstExpiryBoundary()
    {
        var now = DateTime.UtcNow;
        var session = UserSession.Create(ValidUserId, now, TimeSpan.FromMinutes(30));
        var expiresAt = session.ExpiresAtUtc;

        Assert.False(session.IsExpired(expiresAt.AddSeconds(-1)));
        Assert.True(session.IsExpired(expiresAt));
        Assert.True(session.IsExpired(expiresAt.AddSeconds(1)));
    }

    [Fact]
    public void IsActive_WhenActiveUnrevokedAndUnexpired_ReturnsTrue()
    {
        var now = DateTime.UtcNow;
        var session = UserSession.Create(ValidUserId, now, DefaultLifetime);

        Assert.True(session.IsActive(now.AddHours(2)));
    }

    [Fact]
    public void IsActive_WhenExpired_ReturnsFalse()
    {
        var now = DateTime.UtcNow;
        var session = UserSession.Create(ValidUserId, now, TimeSpan.FromHours(1));

        Assert.False(session.IsActive(now.AddHours(2)));
    }

    [Fact]
    public void IsActive_WhenRevokedPriorToExpiry_ReturnsFalse()
    {
        var now = DateTime.UtcNow;
        var session = UserSession.Create(ValidUserId, now, DefaultLifetime);
        session.Revoke(SessionRevocationReason.UserLogout, now.AddHours(1));

        Assert.True(session.IsRevoked);
        Assert.False(session.IsActive(now.AddHours(2)));
    }

    [Fact]
    public void Revoke_WithValidReason_TransitionsToRevokedAndBumpsVersion()
    {
        var now = DateTime.UtcNow;
        var session = UserSession.Create(ValidUserId, now, DefaultLifetime);
        var initialVersion = session.Version;

        var revoked = session.Revoke(SessionRevocationReason.UserLogout, now);

        Assert.True(revoked);
        Assert.True(session.IsRevoked);
        Assert.Equal(now, session.RevokedAtUtc);
        Assert.Equal(SessionRevocationReason.UserLogout, session.RevocationReason);
        Assert.Equal(initialVersion + 1, session.Version);
    }

    [Fact]
    public void Revoke_WhenAlreadyRevoked_IsIdempotentAndDoesNotOverwriteInitialReason()
    {
        var now = DateTime.UtcNow;
        var session = UserSession.Create(ValidUserId, now, DefaultLifetime);

        var firstRevoke = session.Revoke(SessionRevocationReason.TokenReplayDetected, now);
        var originalRevokedAt = session.RevokedAtUtc;
        var originalVersion = session.Version;

        var secondRevoke = session.Revoke(SessionRevocationReason.AdminRevoked, now.AddMinutes(5));

        Assert.True(firstRevoke);
        Assert.False(secondRevoke);
        Assert.Equal(originalRevokedAt, session.RevokedAtUtc);
        Assert.Equal(SessionRevocationReason.TokenReplayDetected, session.RevocationReason);
        Assert.Equal(originalVersion, session.Version);
    }

    [Theory]
    [InlineData(SessionRevocationReason.UserLogout)]
    [InlineData(SessionRevocationReason.PasswordChanged)]
    [InlineData(SessionRevocationReason.SecurityStampMismatch)]
    [InlineData(SessionRevocationReason.AccountSuspended)]
    [InlineData(SessionRevocationReason.AccountDeactivated)]
    [InlineData(SessionRevocationReason.TokenReplayDetected)]
    [InlineData(SessionRevocationReason.AdminRevoked)]
    [InlineData(SessionRevocationReason.Expired)]
    public void Revoke_WithAllApprovedReasons_Succeeds(string validReason)
    {
        var session = UserSession.Create(ValidUserId, DateTime.UtcNow, DefaultLifetime);
        var revoked = session.Revoke(validReason, DateTime.UtcNow);

        Assert.True(revoked);
        Assert.True(session.IsRevoked);
        Assert.Equal(validReason, session.RevocationReason);
    }

    [Theory]
    [InlineData("ArbitraryReason")]
    [InlineData("unknown_reason")]
    [InlineData("UserRequestedLogout")]
    [InlineData("MaliciousActivity")]
    public void Revoke_WithUnapprovedStringReason_ThrowsArgumentException(string unapprovedReason)
    {
        var session = UserSession.Create(ValidUserId, DateTime.UtcNow, DefaultLifetime);

        Assert.Throws<ArgumentException>(() =>
            session.Revoke(unapprovedReason, DateTime.UtcNow));
    }

    [Theory]
    [InlineData(SessionRevocationReasonType.UserLogout, SessionRevocationReason.UserLogout)]
    [InlineData(SessionRevocationReasonType.PasswordChanged, SessionRevocationReason.PasswordChanged)]
    [InlineData(SessionRevocationReasonType.TokenReplayDetected, SessionRevocationReason.TokenReplayDetected)]
    public void Revoke_WithTypedReasonEnum_Succeeds(SessionRevocationReasonType type, string expectedReason)
    {
        var session = UserSession.Create(ValidUserId, DateTime.UtcNow, DefaultLifetime);
        var revoked = session.Revoke(type, DateTime.UtcNow);

        Assert.True(revoked);
        Assert.True(session.IsRevoked);
        Assert.Equal(expectedReason, session.RevocationReason);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(999)]
    [InlineData(-1)]
    public void Revoke_WithUndefinedTypedReasonEnum_ThrowsArgumentOutOfRangeException(int invalidReasonType)
    {
        var session = UserSession.Create(ValidUserId, DateTime.UtcNow, DefaultLifetime);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            session.Revoke((SessionRevocationReasonType)invalidReasonType, DateTime.UtcNow));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Revoke_WithNullOrWhitespaceReason_ThrowsArgumentException(string? invalidReason)
    {
        var session = UserSession.Create(ValidUserId, DateTime.UtcNow, DefaultLifetime);

        Assert.ThrowsAny<ArgumentException>(() =>
            session.Revoke(invalidReason!, DateTime.UtcNow));
    }

    [Fact]
    public void AllowedReasons_CannotBeMutatedThroughCastOrPublicApi()
    {
        // 1. Backing type is genuinely an immutable FrozenSet<string>
        Assert.IsAssignableFrom<System.Collections.Frozen.FrozenSet<string>>(SessionRevocationReason.AllowedReasons);

        // 2. Casting to mutable HashSet throws InvalidCastException
        Assert.Throws<InvalidCastException>(() =>
            (HashSet<string>)(object)SessionRevocationReason.AllowedReasons);

        // 3. Casting to ICollection<string> has IsReadOnly = true and Add() throws NotSupportedException
        var collection = (ICollection<string>)SessionRevocationReason.AllowedReasons;
        Assert.True(collection.IsReadOnly);
        Assert.Throws<NotSupportedException>(() => collection.Add("UnapprovedReasonAddedViaCast"));
    }

    [Fact]
    public void DomainInvariants_UserSessionPropertiesMustNotHavePublicSetters()
    {
        var properties = typeof(UserSession).GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
        Assert.NotEmpty(properties);

        foreach (var prop in properties)
        {
            var setMethod = prop.GetSetMethod(nonPublic: false);
            Assert.True(
                setMethod == null,
                $"Property '{prop.Name}' on '{nameof(UserSession)}' must not have a public setter.");
        }
    }

    [Fact]
    public void ToString_ReturnsSafeSummaryRepresentation()
    {
        var session = UserSession.Create(ValidUserId, DateTime.UtcNow, DefaultLifetime);
        var repr = session.ToString();

        Assert.Contains(session.Id.ToString(), repr);
        Assert.Contains(ValidUserId.ToString(), repr);
        Assert.Contains("Active", repr);
    }
}
