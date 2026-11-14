namespace MaintenX.UnitTests.Application.Auth;

using MaintenX.Api.Application.Auth.Models;
using MaintenX.Api.Application.Auth.Services;
using MaintenX.Api.Application.Auth.Validation;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Configuration;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using ISecurityStampValidator = MaintenX.Api.Common.Security.ISecurityStampValidator;

public class AuthenticationServiceUnitTests
{
    private sealed class FakeSecurityStampValidator : ISecurityStampValidator
    {
        public Task<bool> ValidateAsync(Guid userId, string securityStamp, CancellationToken cancellationToken = default)
            => Task.FromResult(true);

        public void Invalidate(Guid userId) { }
    }

    private static AuthenticationService CreateUnitService(MaintenXDbContext? dbContext = null)
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=dummy;Username=dummy;Password=dummy")
            .Options;

        var context = dbContext ?? new MaintenXDbContext(options);
        var hasher = new PasswordHasher<User>();
        var pwdService = new PasswordSecurityService(hasher);
        var jwtOptions = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "test-key-id-v1",
            SigningKey = Convert.ToBase64String(new byte[32]),
            AccessTokenLifetimeMinutes = 15
        };
        var jwtOptionsWrapper = Options.Create(jwtOptions);
        var jwtKeyRing = new JwtKeyRing(jwtOptionsWrapper);
        var jwtService = new JwtTokenService(jwtKeyRing, jwtOptionsWrapper);
        var refreshTokenService = new RefreshTokenService();
        var stampValidator = new FakeSecurityStampValidator();

        return new AuthenticationService(
            context,
            pwdService,
            jwtService,
            refreshTokenService,
            stampValidator,
            TimeProvider.System,
            NullLogger<AuthenticationService>.Instance);
    }

    [Fact]
    public void PasswordValidation_RejectsPasswordsShorterThan12Characters()
    {
        var ex = Assert.Throws<ArgumentException>(() => PasswordValidation.Validate("Short1!"));
        Assert.Contains("between 12 and 128", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Short1!", ex.Message);
    }

    [Fact]
    public void PasswordValidation_RejectsPasswordsLongerThan128Characters()
    {
        var longPassword = new string('a', 129);
        var ex = Assert.Throws<ArgumentException>(() => PasswordValidation.Validate(longPassword));
        Assert.Contains("128 characters", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(longPassword, ex.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void PasswordValidation_RejectsEmptyOrWhitespacePasswords(string? emptyPassword)
    {
        var ex = Assert.Throws<ArgumentException>(() => PasswordValidation.Validate(emptyPassword));
        Assert.Contains("Password cannot be empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PasswordValidation_AcceptsValidPasswordLengths()
    {
        var minLengthPass = new string('p', 12);
        var maxLengthPass = new string('p', 128);

        // Should not throw
        PasswordValidation.Validate(minLengthPass);
        PasswordValidation.Validate(maxLengthPass);
        PasswordValidation.Validate("CorrectHorseBatteryStaple123!");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("invalid-email")]
    [InlineData("missing@domain")]
    [InlineData("@missinguser.com")]
    public async Task RegisterAsync_RejectsInvalidEmail_ThrowsArgumentException(string? email)
    {
        var sut = CreateUnitService();
        await Assert.ThrowsAnyAsync<ArgumentException>(() => sut.RegisterAsync(email!, "ValidPassword123!"));
    }

    [Fact]
    public async Task RegisterAsync_RejectsShortPassword_ThrowsArgumentException()
    {
        var sut = CreateUnitService();
        await Assert.ThrowsAnyAsync<ArgumentException>(() => sut.RegisterAsync("user@example.com", "short"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("not-an-email")]
    public async Task LoginAsync_RejectsInvalidEmail_ThrowsArgumentException(string? email)
    {
        var sut = CreateUnitService();
        await Assert.ThrowsAnyAsync<ArgumentException>(() => sut.LoginAsync(email!, "ValidPassword123!", "127.0.0.1"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task RefreshTokenAsync_RejectsEmptyToken_ReturnsFailed(string? refreshToken)
    {
        var sut = CreateUnitService();
        var result = await sut.RefreshTokenAsync(refreshToken!, "127.0.0.1");

        Assert.False(result.IsSuccess);
        Assert.Contains("cannot be empty", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LogoutAsync_RejectsEmptySessionId_ReturnsFailed()
    {
        var sut = CreateUnitService();
        var result = await sut.LogoutAsync(Guid.Empty, Guid.NewGuid(), "127.0.0.1");

        Assert.False(result.IsSuccess);
        Assert.Contains("Session ID cannot be empty", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ChangePasswordAsync_RejectsShortNewPassword_ThrowsArgumentException()
    {
        var sut = CreateUnitService();
        await Assert.ThrowsAnyAsync<ArgumentException>(() =>
            sut.ChangePasswordAsync(Guid.NewGuid(), "CurrentPass123!", "short", "127.0.0.1"));
    }

    [Fact]
    public async Task AuthorizedResetPasswordAsync_RejectsShortNewPassword_ThrowsArgumentException()
    {
        var sut = CreateUnitService();
        await Assert.ThrowsAnyAsync<ArgumentException>(() =>
            sut.AuthorizedResetPasswordAsync(Guid.NewGuid(), "short", "127.0.0.1"));
    }

    [Fact]
    public void SensitiveModels_RedactRawTokensInToString()
    {
        var sensitiveToken = "secret-super-sensitive-raw-token-12345";
        var authToken = new AuthTokenResult(sensitiveToken, sensitiveToken, DateTime.UtcNow, DateTime.UtcNow, Guid.NewGuid());

        var authTokenStr = authToken.ToString();
        Assert.DoesNotContain(sensitiveToken, authTokenStr);
        Assert.Contains("[REDACTED]", authTokenStr);

        var loginResult = LoginResult.Success(authToken);
        var loginStr = loginResult.ToString();
        Assert.DoesNotContain(sensitiveToken, loginStr);

        var refreshResult = RefreshTokenResult.Success(authToken);
        var refreshStr = refreshResult.ToString();
        Assert.DoesNotContain(sensitiveToken, refreshStr);
    }
}
