namespace MaintenX.UnitTests.Security;

using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Auth;
using Microsoft.AspNetCore.Identity;
using Xunit;

public class PasswordSecurityServiceTests
{
    private readonly PasswordSecurityService _sut;
    private readonly IPasswordHasher<User> _passwordHasher;

    public PasswordSecurityServiceTests()
    {
        _passwordHasher = new PasswordHasher<User>();
        _sut = new PasswordSecurityService(_passwordHasher);
    }

    [Fact]
    public void HashPassword_WithValidPassword_ReturnsValidHash()
    {
        var user = User.Create("user@example.com", "placeholder-hash");
        var password = "SecurePassword123!";

        var hash = _sut.HashPassword(user, password);

        Assert.False(string.IsNullOrWhiteSpace(hash));
        Assert.NotEqual(password, hash);
    }

    [Fact]
    public void HashPassword_WithNullUser_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _sut.HashPassword(null!, "SecurePassword123!"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void HashPassword_WithInvalidPassword_ThrowsArgumentException(string? invalidPassword)
    {
        var user = User.Create("user@example.com", "placeholder-hash");
        Assert.ThrowsAny<ArgumentException>(() => _sut.HashPassword(user, invalidPassword!));
    }

    [Fact]
    public void VerifyHashedPassword_WithCorrectPassword_ReturnsSuccess()
    {
        var user = User.Create("user@example.com", "placeholder-hash");
        var password = "MyP@ssword2026!";
        var hash = _sut.HashPassword(user, password);

        var result = _sut.VerifyHashedPassword(user, hash, password);

        Assert.Equal(PasswordVerificationResult.Success, result);
    }

    [Fact]
    public void VerifyHashedPassword_WithIncorrectPassword_ReturnsFailed()
    {
        var user = User.Create("user@example.com", "placeholder-hash");
        var correctPassword = "CorrectPassword123!";
        var wrongPassword = "WrongPassword456!";
        var hash = _sut.HashPassword(user, correctPassword);

        var result = _sut.VerifyHashedPassword(user, hash, wrongPassword);

        Assert.Equal(PasswordVerificationResult.Failed, result);
    }

    [Theory]
    [InlineData("", "password")]
    [InlineData("   ", "password")]
    [InlineData("hash", "")]
    [InlineData("hash", "   ")]
    public void VerifyHashedPassword_WithWhitespaceInputs_ReturnsFailedWithoutThrowing(string hash, string password)
    {
        var user = User.Create("user@example.com", "placeholder-hash");

        var result = _sut.VerifyHashedPassword(user, hash, password);

        Assert.Equal(PasswordVerificationResult.Failed, result);
    }

    [Fact]
    public void VerifyDummyPassword_ExecutesSuccessfullyWithoutException()
    {
        // Executes without throwing and takes full cryptographic iterations
        var exception = Record.Exception(() => _sut.VerifyDummyPassword("AttemptedPassword123!"));
        Assert.Null(exception);

        // Also handles null/empty safely
        var emptyException = Record.Exception(() => _sut.VerifyDummyPassword(""));
        Assert.Null(emptyException);
    }

    [Fact]
    public void DummyHash_IsPrecomputedValidHash()
    {
        Assert.False(string.IsNullOrWhiteSpace(_sut.DummyHash));

        // Verifying against dummy hash using dummy user succeeds with the correct password or fails with wrong password
        var dummyUser = new User();
        var verificationResult = _passwordHasher.VerifyHashedPassword(dummyUser, _sut.DummyHash, "wrong-password");
        Assert.Equal(PasswordVerificationResult.Failed, verificationResult);
    }

    [Theory]
    [InlineData(PasswordVerificationResult.SuccessRehashNeeded, true)]
    [InlineData(PasswordVerificationResult.Success, false)]
    [InlineData(PasswordVerificationResult.Failed, false)]
    public void NeedsRehash_ReturnsExpectedBoolean(PasswordVerificationResult result, bool expected)
    {
        Assert.Equal(expected, _sut.NeedsRehash(result));
    }

    [Fact]
    public void ToString_RedactsSecrets()
    {
        var str = _sut.ToString();
        Assert.DoesNotContain("MaintenX-ConstantTime", str);
        Assert.DoesNotContain(_sut.DummyHash, str);
        Assert.Contains("PasswordSecurityService", str);
    }
}
