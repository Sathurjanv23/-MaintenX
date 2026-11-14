namespace MaintenX.UnitTests.Domain.Auth;

using System.Reflection;
using MaintenX.Api.Domain.Auth;
using Xunit;

public class UserTests
{
    private const string ValidEmail = "maintenance.lead@facility.maintenx.internal";
    private const string ValidPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$somehashvalue$anothersecretpart";

    [Fact]
    public void Create_WithValidParameters_InitializesEntityWithExpectedInvariants()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, now);

        Assert.NotEqual(Guid.Empty, user.Id);
        Assert.Equal(ValidEmail, user.Email);
        Assert.Equal(ValidPasswordHash, user.PasswordHash);
        Assert.False(string.IsNullOrWhiteSpace(user.SecurityStamp));
        Assert.Equal(64, user.SecurityStamp.Length); // 32 bytes hex encoded = 64 characters
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.FailedLoginWindowStartedAtUtc);
        Assert.Null(user.LockoutEndUtc);
        Assert.Null(user.LastLoginAtUtc);
        Assert.Equal(now, user.CreatedAtUtc);
        Assert.Equal(now, user.UpdatedAtUtc);
        Assert.Equal(1, user.Version);
    }

    [Fact]
    public void UserStatus_HasOnlyActiveSuspendedDeactivatedValues()
    {
        var names = Enum.GetNames<UserStatus>();
        Assert.Equal(3, names.Length);
        Assert.Contains(nameof(UserStatus.Active), names);
        Assert.Contains(nameof(UserStatus.Suspended), names);
        Assert.Contains(nameof(UserStatus.Deactivated), names);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(99)]
    [InlineData(-1)]
    public void Create_WithUndefinedUserStatus_ThrowsArgumentOutOfRangeException(int invalidStatusValue)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            User.Create(ValidEmail, ValidPasswordHash, (UserStatus)invalidStatusValue));
    }

    [Theory]
    [InlineData("USER@DOMAIN.COM", "user@domain.com")]
    [InlineData("  user.name+tag@sub.domain.org  ", "user.name+tag@sub.domain.org")]
    [InlineData("Technician.123@MaintenX.INTERNAL", "technician.123@maintenx.internal")]
    public void NormalizeAndValidateEmail_WithValidMixedCaseAndWhitespace_NormalizesCorrectly(string raw, string expected)
    {
        var normalized = User.NormalizeAndValidateEmail(raw);
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("notanemail")]
    [InlineData("missingatdomain.com")]
    [InlineData("@nodomain.com")]
    [InlineData("user@")]
    [InlineData("user@domain")]
    [InlineData("user@.domain.com")]
    [InlineData("user@domain.")]
    [InlineData("user space@domain.com")]
    [InlineData("user@domain .com")]
    [InlineData("user@@doubleat.com")]
    public void NormalizeAndValidateEmail_WithInvalidFormats_ThrowsArgumentException(string? invalidEmail)
    {
        Assert.ThrowsAny<ArgumentException>(() => User.NormalizeAndValidateEmail(invalidEmail!));
    }

    [Fact]
    public void NormalizeAndValidateEmail_Exceeding256Characters_ThrowsArgumentException()
    {
        var longLocal = new string('a', 60);
        var longDomain = new string('b', 195) + ".com";
        var tooLongEmail = $"{longLocal}@{longDomain}"; // 60 + 1 + 195 + 4 = 260 chars

        Assert.Throws<ArgumentException>(() => User.NormalizeAndValidateEmail(tooLongEmail));
    }

    [Fact]
    public void NormalizeAndValidateEmail_LocalPartExceeding64Characters_ThrowsArgumentException()
    {
        var longLocal = new string('a', 65);
        var email = $"{longLocal}@domain.com";

        Assert.Throws<ArgumentException>(() => User.NormalizeAndValidateEmail(email));
    }

    [Fact]
    public void IsLockedOut_WhenNoLockoutSet_ReturnsFalse()
    {
        var user = User.Create(ValidEmail, ValidPasswordHash);
        Assert.False(user.IsLockedOut(DateTime.UtcNow));
    }

    [Fact]
    public void RecordFailedLogin_ProgressionWithinRollingWindow_AppliesLockoutAtThreshold()
    {
        var t0 = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, t0);

        // 1st failure at T0
        user.RecordFailedLogin(t0);
        Assert.Equal(1, user.FailedLoginAttempts);
        Assert.Equal(t0, user.FailedLoginWindowStartedAtUtc);
        Assert.Null(user.LockoutEndUtc);
        Assert.False(user.IsLockedOut(t0));

        // 2nd failure at T0 + 2m
        user.RecordFailedLogin(t0.AddMinutes(2));
        Assert.Equal(2, user.FailedLoginAttempts);
        Assert.Equal(t0, user.FailedLoginWindowStartedAtUtc);

        // 3rd failure at T0 + 5m
        user.RecordFailedLogin(t0.AddMinutes(5));
        Assert.Equal(3, user.FailedLoginAttempts);
        Assert.Equal(t0, user.FailedLoginWindowStartedAtUtc);

        // 4th failure at T0 + 10m
        user.RecordFailedLogin(t0.AddMinutes(10));
        Assert.Equal(4, user.FailedLoginAttempts);
        Assert.Equal(t0, user.FailedLoginWindowStartedAtUtc);

        // 5th failure at T0 + 14m (within 15m window) -> triggers lockout
        var tLockout = t0.AddMinutes(14);
        user.RecordFailedLogin(tLockout);
        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.FailedLoginWindowStartedAtUtc);
        Assert.NotNull(user.LockoutEndUtc);
        Assert.Equal(tLockout.Add(User.DefaultLockoutDuration), user.LockoutEndUtc);
        Assert.True(user.IsLockedOut(tLockout));
        Assert.False(user.CanAuthenticate(tLockout));
    }

    [Fact]
    public void RecordFailedLogin_WhenWindowExpires_DiscardsOldFailuresAndStartsNewWindow()
    {
        var t0 = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, t0);

        // 4 failures within first 10 minutes
        for (int i = 0; i < 4; i++)
        {
            user.RecordFailedLogin(t0.AddMinutes(i * 2));
        }
        Assert.Equal(4, user.FailedLoginAttempts);
        Assert.Equal(t0, user.FailedLoginWindowStartedAtUtc);
        Assert.Null(user.LockoutEndUtc);

        // Next failure arrives at T0 + 16m (after the 15m window expired)
        var tNew = t0.AddMinutes(16);
        user.RecordFailedLogin(tNew);

        // Counter MUST reset to 1 and start fresh window at tNew
        Assert.Equal(1, user.FailedLoginAttempts);
        Assert.Equal(tNew, user.FailedLoginWindowStartedAtUtc);
        Assert.Null(user.LockoutEndUtc);
        Assert.False(user.IsLockedOut(tNew));
    }

    [Fact]
    public void RecordFailedLogin_ExactWindowExpiryBoundary_ResetsWindow()
    {
        var t0 = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, t0);

        user.RecordFailedLogin(t0);
        Assert.Equal(1, user.FailedLoginAttempts);

        // Failure arrives exactly at T0 + 15m
        var tExactBoundary = t0.AddMinutes(15);
        user.RecordFailedLogin(tExactBoundary);

        // Exactly at boundary, window has expired -> fresh window starts with 1 attempt
        Assert.Equal(1, user.FailedLoginAttempts);
        Assert.Equal(tExactBoundary, user.FailedLoginWindowStartedAtUtc);
    }

    [Fact]
    public void RecordFailedLogin_WithInvalidParameters_ThrowsArgumentOutOfRangeException()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);

        // maxFailedAttempts <= 0
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            user.RecordFailedLogin(now, maxFailedAttempts: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            user.RecordFailedLogin(now, maxFailedAttempts: -1));

        // lockoutDuration <= Zero
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            user.RecordFailedLogin(now, lockoutDuration: TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            user.RecordFailedLogin(now, lockoutDuration: TimeSpan.FromMinutes(-5)));

        // windowDuration <= Zero
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            user.RecordFailedLogin(now, windowDuration: TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            user.RecordFailedLogin(now, windowDuration: TimeSpan.FromMinutes(-1)));
    }

    [Fact]
    public void RecordFailedLogin_WhenUserSuspendedOrDeactivated_DoesNotAlterState()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Suspended);

        user.RecordFailedLogin(now);

        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.FailedLoginWindowStartedAtUtc);
        Assert.Null(user.LockoutEndUtc);
    }

    [Fact]
    public void RecordSuccessfulLogin_WhenActiveAndNotLocked_ResetsCountersAndUpdatesTimestamp()
    {
        var t0 = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, t0);

        user.RecordFailedLogin(t0);
        user.RecordFailedLogin(t0.AddMinutes(1));
        Assert.Equal(2, user.FailedLoginAttempts);
        Assert.NotNull(user.FailedLoginWindowStartedAtUtc);

        var tSuccess = t0.AddMinutes(5);
        user.RecordSuccessfulLogin(tSuccess);

        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.FailedLoginWindowStartedAtUtc);
        Assert.Null(user.LockoutEndUtc);
        Assert.Equal(tSuccess, user.LastLoginAtUtc);
        Assert.Equal(tSuccess, user.UpdatedAtUtc);
    }

    [Fact]
    public void RecordSuccessfulLogin_WhenLockedOut_ThrowsInvalidOperationException()
    {
        var t0 = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, t0);

        // Force lockout via 5 failures
        for (int i = 0; i < 5; i++)
        {
            user.RecordFailedLogin(t0.AddMinutes(i));
        }
        Assert.True(user.IsLockedOut(t0.AddMinutes(4)));

        Assert.Throws<InvalidOperationException>(() => user.RecordSuccessfulLogin(t0.AddMinutes(5)));
    }

    [Fact]
    public void RecordSuccessfulLogin_WhenSuspended_ThrowsInvalidOperationException()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Suspended);

        Assert.Throws<InvalidOperationException>(() => user.RecordSuccessfulLogin(now));
    }

    [Fact]
    public void ResetFailedLogin_ClearsFailedAttemptsWindowAndActiveLockout()
    {
        var t0 = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, t0);

        for (int i = 0; i < 5; i++)
        {
            user.RecordFailedLogin(t0.AddMinutes(i));
        }
        Assert.NotNull(user.LockoutEndUtc);

        user.ResetFailedLogin(t0.AddMinutes(10));

        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.FailedLoginWindowStartedAtUtc);
        Assert.Null(user.LockoutEndUtc);
        Assert.False(user.IsLockedOut(t0.AddMinutes(10)));
    }

    [Fact]
    public void UpdatePassword_WhenActive_UpdatesHashRotatesStampAndClearsLockout()
    {
        var t0 = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, t0);
        var oldStamp = user.SecurityStamp;

        for (int i = 0; i < 5; i++)
        {
            user.RecordFailedLogin(t0.AddMinutes(i));
        }
        Assert.NotNull(user.LockoutEndUtc);

        var newHash = "$argon2id$v=19$newpasswordhash";
        var tUpdate = t0.AddMinutes(10);
        user.UpdatePassword(newHash, tUpdate);

        Assert.Equal(newHash, user.PasswordHash);
        Assert.NotEqual(oldStamp, user.SecurityStamp);
        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.FailedLoginWindowStartedAtUtc);
        Assert.Null(user.LockoutEndUtc);
        Assert.Equal(tUpdate, user.UpdatedAtUtc);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void UpdatePassword_WithInvalidHash_ThrowsArgumentException(string? invalidHash)
    {
        var user = User.Create(ValidEmail, ValidPasswordHash);
        Assert.ThrowsAny<ArgumentException>(() => user.UpdatePassword(invalidHash!, DateTime.UtcNow));
    }

    [Fact]
    public void UpdatePassword_WhenSuspended_ThrowsInvalidOperationException()
    {
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Suspended);
        Assert.Throws<InvalidOperationException>(() => user.UpdatePassword("newhash", DateTime.UtcNow));
    }

    [Fact]
    public void RotateSecurityStamp_GeneratesNewDistinctStampAndBumpsVersion()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);
        var initialStamp = user.SecurityStamp;
        var initialVersion = user.Version;

        user.RotateSecurityStamp(now);

        Assert.NotEqual(initialStamp, user.SecurityStamp);
        Assert.Equal(initialVersion + 1, user.Version);
        Assert.Equal(now, user.UpdatedAtUtc);
    }

    [Fact]
    public void StatusTransitions_LifecycleWorkflow()
    {
        var now = DateTime.UtcNow;
        // User starts Active
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, now);
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.True(user.CanAuthenticate(now));

        // 1. Active -> Suspended (rotates security stamp)
        var stampBeforeSuspend = user.SecurityStamp;
        user.Suspend(now);
        Assert.Equal(UserStatus.Suspended, user.Status);
        Assert.NotEqual(stampBeforeSuspend, user.SecurityStamp);
        Assert.False(user.CanAuthenticate(now));

        // 2. Suspended -> Reactivate (rotates security stamp)
        var stampBeforeReactivate = user.SecurityStamp;
        user.Reactivate(now);
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.NotEqual(stampBeforeReactivate, user.SecurityStamp);
        Assert.True(user.CanAuthenticate(now));

        // 3. Active -> Deactivate (Terminal state)
        user.Deactivate(now);
        Assert.Equal(UserStatus.Deactivated, user.Status);
        Assert.False(user.CanAuthenticate(now));

        // 4. Deactivated account cannot be reactivated or suspended
        Assert.Throws<InvalidOperationException>(() => user.Reactivate(now));
        Assert.Throws<InvalidOperationException>(() => user.Suspend(now));
    }

    [Fact]
    public void Reactivate_WhenNotSuspended_ThrowsInvalidOperationException()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Active, now);

        Assert.Throws<InvalidOperationException>(() => user.Reactivate(now));
    }

    [Fact]
    public void DomainInvariants_UserPropertiesMustNotHavePublicSetters()
    {
        var properties = typeof(User).GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Assert.NotEmpty(properties);

        foreach (var prop in properties)
        {
            var setMethod = prop.GetSetMethod(nonPublic: false);
            Assert.True(
                setMethod == null,
                $"Property '{prop.Name}' on '{nameof(User)}' must not have a public setter.");
        }
    }

    [Fact]
    public void ToString_StrictlyOmitsPasswordHashAndSecurityStamp()
    {
        var user = User.Create(ValidEmail, ValidPasswordHash);
        var representation = user.ToString();

        Assert.Contains(user.Id.ToString(), representation);
        Assert.Contains(ValidEmail, representation);
        Assert.DoesNotContain(ValidPasswordHash, representation);
        Assert.DoesNotContain(user.SecurityStamp, representation);
    }
}
