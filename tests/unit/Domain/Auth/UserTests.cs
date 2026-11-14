namespace MaintenX.UnitTests.Domain.Auth;

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
        Assert.Null(user.LockoutEndUtc);
        Assert.Null(user.LastLoginAtUtc);
        Assert.Equal(now, user.CreatedAtUtc);
        Assert.Equal(now, user.UpdatedAtUtc);
        Assert.Equal(1, user.Version);
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
    public void IsLockedOut_WhenLockoutInFuture_ReturnsTrue()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);
        user.LockoutEndUtc = now.AddMinutes(15);

        Assert.True(user.IsLockedOut(now));
        Assert.False(user.CanAuthenticate(now));
    }

    [Fact]
    public void IsLockedOut_WhenLockoutPassed_ReturnsFalse()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);
        user.LockoutEndUtc = now.AddMinutes(-1);

        Assert.False(user.IsLockedOut(now));
        Assert.True(user.CanAuthenticate(now));
    }

    [Fact]
    public void RecordFailedLogin_BelowThreshold_IncrementsCountWithoutLockout()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);

        user.RecordFailedLogin(now, maxFailedAttempts: 5);

        Assert.Equal(1, user.FailedLoginAttempts);
        Assert.Null(user.LockoutEndUtc);
        Assert.False(user.IsLockedOut(now));
        Assert.Equal(2, user.Version);
    }

    [Fact]
    public void RecordFailedLogin_ReachingThreshold_AppliesLockout()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);

        for (int i = 1; i <= 5; i++)
        {
            user.RecordFailedLogin(now, maxFailedAttempts: 5, lockoutDuration: TimeSpan.FromMinutes(20));
        }

        Assert.Equal(5, user.FailedLoginAttempts);
        Assert.NotNull(user.LockoutEndUtc);
        Assert.Equal(now.AddMinutes(20), user.LockoutEndUtc);
        Assert.True(user.IsLockedOut(now));
        Assert.False(user.CanAuthenticate(now));
    }

    [Fact]
    public void RecordFailedLogin_WhenUserSuspendedOrDeactivated_DoesNotAlterLockoutState()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.Suspended);

        user.RecordFailedLogin(now, maxFailedAttempts: 5);

        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.LockoutEndUtc);
    }

    [Fact]
    public void RecordSuccessfulLogin_WhenActiveAndNotLocked_ResetsCountersAndUpdatesTimestamp()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);
        user.FailedLoginAttempts = 3;

        user.RecordSuccessfulLogin(now);

        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.LockoutEndUtc);
        Assert.Equal(now, user.LastLoginAtUtc);
        Assert.Equal(now, user.UpdatedAtUtc);
    }

    [Fact]
    public void RecordSuccessfulLogin_WhenLockedOut_ThrowsInvalidOperationException()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);
        user.LockoutEndUtc = now.AddMinutes(10);

        Assert.Throws<InvalidOperationException>(() => user.RecordSuccessfulLogin(now));
    }

    [Fact]
    public void ResetFailedLogin_ClearsFailedAttemptsAndActiveLockout()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);
        user.FailedLoginAttempts = 4;
        user.LockoutEndUtc = now.AddMinutes(15);

        user.ResetFailedLogin(now);

        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.LockoutEndUtc);
        Assert.False(user.IsLockedOut(now));
    }

    [Fact]
    public void UpdatePassword_WhenActive_UpdatesHashRotatesStampAndClearsLockout()
    {
        var now = DateTime.UtcNow;
        var user = User.Create(ValidEmail, ValidPasswordHash);
        var oldStamp = user.SecurityStamp;
        user.FailedLoginAttempts = 3;
        user.LockoutEndUtc = now.AddMinutes(15);

        var newHash = "$argon2id$v=19$newpasswordhash";
        user.UpdatePassword(newHash, now);

        Assert.Equal(newHash, user.PasswordHash);
        Assert.NotEqual(oldStamp, user.SecurityStamp);
        Assert.Equal(0, user.FailedLoginAttempts);
        Assert.Null(user.LockoutEndUtc);
        Assert.Equal(now, user.UpdatedAtUtc);
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
        var user = User.Create(ValidEmail, ValidPasswordHash, UserStatus.PendingVerification);

        // 1. PendingVerification -> Active
        user.Activate(now);
        Assert.Equal(UserStatus.Active, user.Status);

        // 2. Active -> Suspended (rotates security stamp)
        var stampBeforeSuspend = user.SecurityStamp;
        user.Suspend(now);
        Assert.Equal(UserStatus.Suspended, user.Status);
        Assert.NotEqual(stampBeforeSuspend, user.SecurityStamp);
        Assert.False(user.CanAuthenticate(now));

        // 3. Suspended -> Reactivate
        var stampBeforeReactivate = user.SecurityStamp;
        user.Reactivate(now);
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.NotEqual(stampBeforeReactivate, user.SecurityStamp);
        Assert.True(user.CanAuthenticate(now));

        // 4. Active -> Deactivate (Terminal state)
        user.Deactivate(now);
        Assert.Equal(UserStatus.Deactivated, user.Status);
        Assert.False(user.CanAuthenticate(now));

        // 5. Deactivated account cannot be reactivated or activated
        Assert.Throws<InvalidOperationException>(() => user.Activate(now));
        Assert.Throws<InvalidOperationException>(() => user.Reactivate(now));
        Assert.Throws<InvalidOperationException>(() => user.Suspend(now));
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
