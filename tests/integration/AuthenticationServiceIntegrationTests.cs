namespace MaintenX.IntegrationTests;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Application.Auth.Models;
using MaintenX.Api.Application.Auth.Services;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Configuration;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using ISecurityStampValidator = MaintenX.Api.Common.Security.ISecurityStampValidator;
using SecurityStampValidator = MaintenX.Api.Common.Security.SecurityStampValidator;

/// <summary>
/// Comprehensive integration tests for <see cref="AuthenticationService"/> on real PostgreSQL 16.
/// Validates registration timing-attack mitigation, duplicate race handling, login failure counters and lockout,
/// transparent rehash without stamp rotation, single-flight refresh token rotation with critical replay precedence,
/// idempotent logout with ownership validation, and password mutations with session family revocation.
/// </summary>
public class AuthenticationServiceIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public AuthenticationServiceIntegrationTests()
    {
        _configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        var (admin, test) = TestDatabaseGuard.ValidateConnectionConfiguration(_configuration);
        _adminConnectionString = admin;
        _testConnectionString = test;
    }

    public async Task InitializeAsync()
    {
        var (dbName, connStr) = await TestDatabaseGuard.ProvisionAndInitializeAsync(
            _adminConnectionString,
            _testConnectionString,
            _configuration,
            async (conn) =>
            {
                var options = new DbContextOptionsBuilder<MaintenXDbContext>()
                    .UseNpgsql(conn)
                    .Options;

                using var context = new MaintenXDbContext(options);
                await context.Database.MigrateAsync();
            });

        _databaseName = dbName;
        _isolatedConnectionString = connStr;
    }

    public async Task DisposeAsync()
    {
        if (!string.IsNullOrWhiteSpace(_databaseName))
        {
            await TestDatabaseGuard.DropDatabaseSafelyAsync(_databaseName, _adminConnectionString);
        }
    }

    private MaintenXDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return new MaintenXDbContext(options);
    }

    private AuthenticationService CreateAuthenticationService(
        MaintenXDbContext context,
        IMemoryCache? cache = null,
        TimeProvider? timeProvider = null,
        IPasswordSecurityService? customPasswordSecurityService = null)
    {
        var passwordHasher = new PasswordHasher<User>();
        var passwordSecurityService = customPasswordSecurityService ?? new PasswordSecurityService(passwordHasher);
        var jwtOptions = new JwtOptions
        {
            Issuer = "https://api.maintenx.internal",
            Audience = "https://maintenx.internal",
            KeyId = "test-integration-key-v1",
            SigningKey = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("super-secret-integration-test-key-32b!")),
            AccessTokenLifetimeMinutes = 15
        };
        var jwtOptionsWrapper = Options.Create(jwtOptions);
        var jwtKeyRing = new JwtKeyRing(jwtOptionsWrapper, timeProvider);
        var jwtTokenService = new JwtTokenService(jwtKeyRing, jwtOptionsWrapper, timeProvider);
        var refreshTokenService = new RefreshTokenService();
        var memoryCache = cache ?? new MemoryCache(new MemoryCacheOptions());
        var stampStore = new EfUserSecurityStampStore(context);
        var stampValidator = new SecurityStampValidator(stampStore, memoryCache, NullLogger<SecurityStampValidator>.Instance);

        return new AuthenticationService(
            context,
            passwordSecurityService,
            jwtTokenService,
            refreshTokenService,
            stampValidator,
            timeProvider ?? TimeProvider.System,
            NullLogger<AuthenticationService>.Instance);
    }

    // =========================================================================
    // 1. REGISTRATION WORKFLOW TESTS
    // =========================================================================

    [Fact]
    public async Task RegisterAsync_ValidInputs_CreatesUserAndSecurityAuditEvent()
    {
        var email = "newuser-reg@example.com";
        var password = "SecurePassword123!";

        await using var context = CreateDbContext();
        var sut = CreateAuthenticationService(context);

        var result = await sut.RegisterAsync(email, password, "192.168.1.50");

        Assert.True(result.IsSuccess);
        Assert.Equal(RegistrationResult.DefaultGenericMessage, result.Message);

        // Verify persistence in separate context
        await using var verifyContext = CreateDbContext();
        var user = await verifyContext.Users.SingleOrDefaultAsync(u => u.Email == email);
        Assert.NotNull(user);
        Assert.Equal(UserStatus.Active, user.Status);
        Assert.False(string.IsNullOrWhiteSpace(user.PasswordHash));
        Assert.NotEqual(password, user.PasswordHash);
        Assert.False(string.IsNullOrWhiteSpace(user.SecurityStamp));

        var audit = await verifyContext.SecurityAuditEvents
            .SingleOrDefaultAsync(e => e.UserId == user.Id && e.EventType == SecurityAuditEventType.UserRegistered);
        Assert.NotNull(audit);
        Assert.Equal("192.168.1.50", audit.ClientIp);
        Assert.Equal(SecurityAuditMetadata.Reasons.UserRegistration, audit.Reason);
        Assert.Equal(SecurityAuditMetadata.Actions.Permit, audit.ActionTaken);
    }

    [Fact]
    public async Task RegisterAsync_DuplicateEmail_ReturnsGenericResponseAndAuditsDenyWithoutEnumeration()
    {
        var email = "duplicate-reg@example.com";
        var password = "SecurePassword123!";

        await using (var context1 = CreateDbContext())
        {
            var sut1 = CreateAuthenticationService(context1);
            await sut1.RegisterAsync(email, password, "192.168.1.1");
        }

        // Duplicate registration attempt
        await using (var context2 = CreateDbContext())
        {
            var sut2 = CreateAuthenticationService(context2);
            var result = await sut2.RegisterAsync(email, password, "192.168.1.2");

            Assert.True(result.IsSuccess);
            Assert.Equal(RegistrationResult.DefaultGenericMessage, result.Message);
        }

        await using (var verifyContext = CreateDbContext())
        {
            var users = await verifyContext.Users.Where(u => u.Email == email).ToListAsync();
            Assert.Single(users);

            var audits = await verifyContext.SecurityAuditEvents
                .Where(e => e.EventType == SecurityAuditEventType.UserRegistered)
                .OrderBy(e => e.CreatedAtUtc)
                .ToListAsync();

            Assert.True(audits.Count >= 2);
            var duplicateAudit = audits.Last();
            Assert.Null(duplicateAudit.UserId);
            Assert.Equal("192.168.1.2", duplicateAudit.ClientIp);
            Assert.Equal(SecurityAuditMetadata.Actions.Deny, duplicateAudit.ActionTaken);
        }
    }

    // =========================================================================
    // 2. LOGIN WORKFLOW TESTS
    // =========================================================================

    [Fact]
    public async Task LoginAsync_ValidCredentials_IssuesJwtWithRequiredClaimsAndResetsFailedAttempts()
    {
        var email = "valid-login@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password, "10.0.0.1");
        }

        await using var loginContext = CreateDbContext();
        var sut = CreateAuthenticationService(loginContext);

        var loginResult = await sut.LoginAsync(email, password, "10.0.0.1");

        Assert.True(loginResult.IsSuccess);
        Assert.NotNull(loginResult.Tokens);
        Assert.False(string.IsNullOrWhiteSpace(loginResult.Tokens.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(loginResult.Tokens.RefreshToken));

        // Validate JWT Claims
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(loginResult.Tokens.AccessToken);
        Assert.Equal("test-integration-key-v1", jwt.Header.Kid);
        Assert.Equal(loginResult.Tokens.SessionId.ToString("D"), jwt.Claims.First(c => c.Type == "sid").Value);
        Assert.NotEmpty(jwt.Claims.First(c => c.Type == "sst").Value);
        Assert.Equal("https://api.maintenx.internal", jwt.Issuer);
        Assert.Contains(jwt.Audiences, a => a == "https://maintenx.internal");

        // Verify UserSession & RefreshToken state in PostgreSQL
        await using var verifyContext = CreateDbContext();
        var session = await verifyContext.UserSessions
            .SingleOrDefaultAsync(s => s.Id == loginResult.Tokens.SessionId);
        Assert.NotNull(session);
        Assert.True(session.IsActive(DateTime.UtcNow));

        var tokens = await verifyContext.RefreshTokens
            .Where(t => t.SessionId == session.Id)
            .ToListAsync();
        Assert.Single(tokens);
        Assert.True(tokens.First().IsActive(DateTime.UtcNow));

        var loginAudit = await verifyContext.SecurityAuditEvents
            .SingleOrDefaultAsync(e => e.EventType == SecurityAuditEventType.LoginSuccess && e.SessionId == session.Id);
        Assert.NotNull(loginAudit);
        Assert.Equal(SecurityAuditMetadata.Actions.SessionCreated, loginAudit.ActionTaken);
    }

    [Fact]
    public async Task LoginAsync_InvalidPassword_IncrementsFailedAttemptsAndAuditsFailure()
    {
        var email = "invalid-pass-login@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password);
        }

        await using var loginContext = CreateDbContext();
        var sut = CreateAuthenticationService(loginContext);

        var result = await sut.LoginAsync(email, "WrongPassword123!", "10.0.0.2");

        Assert.False(result.IsSuccess);
        Assert.False(result.IsLockedOut);
        Assert.Equal("Invalid email or password.", result.ErrorMessage);

        await using var verifyContext = CreateDbContext();
        var user = await verifyContext.Users.SingleAsync(u => u.Email == email);
        Assert.Equal(1, user.FailedLoginAttempts);

        var failureAudit = await verifyContext.SecurityAuditEvents
            .SingleOrDefaultAsync(e => e.EventType == SecurityAuditEventType.LoginFailed && e.UserId == user.Id);
        Assert.NotNull(failureAudit);
        Assert.Equal("10.0.0.2", failureAudit.ClientIp);
        Assert.Equal(SecurityAuditMetadata.Actions.Deny, failureAudit.ActionTaken);
    }

    [Fact]
    public async Task LoginAsync_FiveFailedAttempts_EnforcesFifteenMinuteLockout()
    {
        var email = "lockout-login@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password);
        }

        // Execute 4 failed attempts
        for (int i = 0; i < 4; i++)
        {
            await using var failContext = CreateDbContext();
            var failSut = CreateAuthenticationService(failContext);
            var res = await failSut.LoginAsync(email, "WrongPassword123!");
            Assert.False(res.IsSuccess);
            Assert.False(res.IsLockedOut);
        }

        // 5th failed attempt triggers lockout
        await using (var lockContext = CreateDbContext())
        {
            var lockSut = CreateAuthenticationService(lockContext);
            var res5 = await lockSut.LoginAsync(email, "WrongPassword123!");
            Assert.False(res5.IsSuccess);
            Assert.True(res5.IsLockedOut);
            Assert.NotNull(res5.LockoutEndUtc);
        }

        // 6th attempt (even with CORRECT password) is locked out
        await using (var postContext = CreateDbContext())
        {
            var postSut = CreateAuthenticationService(postContext);
            var res6 = await postSut.LoginAsync(email, password);
            Assert.False(res6.IsSuccess);
            Assert.True(res6.IsLockedOut);
        }

        await using var verifyContext = CreateDbContext();
        var user = await verifyContext.Users.SingleAsync(u => u.Email == email);
        Assert.NotNull(user.LockoutEndUtc);
        Assert.True(user.LockoutEndUtc > DateTime.UtcNow);

        var lockoutAudit = await verifyContext.SecurityAuditEvents
            .SingleOrDefaultAsync(e => e.EventType == SecurityAuditEventType.AccountLockedOut && e.UserId == user.Id);
        Assert.NotNull(lockoutAudit);
    }

    [Fact]
    public async Task LoginAsync_NonexistentUser_ExecutesDummyHashAndReturnsInvalidCredentials()
    {
        await using var loginContext = CreateDbContext();
        var sut = CreateAuthenticationService(loginContext);

        var result = await sut.LoginAsync("nonexistent-user@example.com", "SomePassword123!", "127.0.0.1");

        Assert.False(result.IsSuccess);
        Assert.Equal("Invalid email or password.", result.ErrorMessage);

        await using var verifyContext = CreateDbContext();
        var audits = await verifyContext.SecurityAuditEvents
            .Where(e => e.EventType == SecurityAuditEventType.LoginFailed)
            .ToListAsync();

        Assert.Contains(audits, a => a.UserId == null && a.ClientIp == "127.0.0.1");
    }

    // =========================================================================
    // 3. REFRESH TOKEN ROTATION & REPLAY PRECEDENCE TESTS
    // =========================================================================

    [Fact]
    public async Task RefreshTokenAsync_ValidToken_RotatesAtomicallyAndCapsExpiryAtSessionExpiry()
    {
        var email = "refresh-test@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password);
        }

        AuthTokenResult initialTokens;
        await using (var loginContext = CreateDbContext())
        {
            var loginSut = CreateAuthenticationService(loginContext);
            var loginRes = await loginSut.LoginAsync(email, password);
            initialTokens = loginRes.Tokens!;
        }

        await using var refreshContext = CreateDbContext();
        var sut = CreateAuthenticationService(refreshContext);

        var refreshResult = await sut.RefreshTokenAsync(initialTokens.RefreshToken, "192.168.1.100");

        Assert.True(refreshResult.IsSuccess);
        Assert.NotNull(refreshResult.Tokens);
        Assert.NotEqual(initialTokens.RefreshToken, refreshResult.Tokens.RefreshToken);

        await using var verifyContext = CreateDbContext();
        var session = await verifyContext.UserSessions
            .SingleAsync(s => s.Id == initialTokens.SessionId);

        var tokens = await verifyContext.RefreshTokens
            .Where(t => t.SessionId == session.Id)
            .ToListAsync();

        Assert.Equal(2, tokens.Count);
        var oldToken = tokens.First(t => t.IsRotated);
        var newToken = tokens.First(t => !t.IsRotated);

        Assert.True(oldToken.IsRotated);
        Assert.True(oldToken.IsRevoked);
        Assert.True(newToken.IsActive(DateTime.UtcNow));
        Assert.True(newToken.ExpiresAtUtc <= session.ExpiresAtUtc);

        var refreshAudit = await verifyContext.SecurityAuditEvents
            .SingleOrDefaultAsync(e => e.EventType == SecurityAuditEventType.TokenRefreshed && e.SessionId == session.Id);
        Assert.NotNull(refreshAudit);
        Assert.Equal("192.168.1.100", refreshAudit.ClientIp);
    }

    [Fact]
    public async Task RefreshTokenAsync_TokenReplayDetected_RevokesSessionFamilyAndRecordsAuditEvent()
    {
        var email = "replay-test@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password);
        }

        AuthTokenResult initialTokens;
        await using (var loginContext = CreateDbContext())
        {
            var loginSut = CreateAuthenticationService(loginContext);
            var loginRes = await loginSut.LoginAsync(email, password);
            initialTokens = loginRes.Tokens!;
        }

        // 1. Normal rotation (rotates initialTokens.RefreshToken)
        AuthTokenResult rotatedTokens;
        await using (var rotContext = CreateDbContext())
        {
            var rotSut = CreateAuthenticationService(rotContext);
            var rotRes = await rotSut.RefreshTokenAsync(initialTokens.RefreshToken);
            Assert.True(rotRes.IsSuccess);
            rotatedTokens = rotRes.Tokens!;
        }

        // 2. Replay attack: Attacker presents already-rotated initialTokens.RefreshToken
        await using (var replayContext = CreateDbContext())
        {
            var replaySut = CreateAuthenticationService(replayContext);
            var replayResult = await replaySut.RefreshTokenAsync(initialTokens.RefreshToken, "10.66.66.66");

            Assert.False(replayResult.IsSuccess);
            Assert.True(replayResult.IsReplayDetected);
            Assert.Contains("replay", replayResult.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        }

        // 3. Verify session family is completely revoked
        await using (var verifyContext = CreateDbContext())
        {
            var session = await verifyContext.UserSessions
                .SingleAsync(s => s.Id == initialTokens.SessionId);

            Assert.True(session.IsRevoked);
            Assert.Equal(SessionRevocationReason.TokenReplayDetected, session.RevocationReason);

            var tokens = await verifyContext.RefreshTokens
                .Where(t => t.SessionId == session.Id)
                .ToListAsync();

            Assert.All(tokens, t => Assert.True(t.IsRevoked || t.IsRotated));

            var replayAudit = await verifyContext.SecurityAuditEvents
                .SingleOrDefaultAsync(e => e.EventType == SecurityAuditEventType.TokenReplayDetected && e.SessionId == session.Id);
            Assert.NotNull(replayAudit);
            Assert.Equal("10.66.66.66", replayAudit.ClientIp);
            Assert.Equal(SecurityAuditMetadata.Actions.SessionRevoked, replayAudit.ActionTaken);
        }

        // 4. Legitimate user presenting rotatedTokens is now also rejected because session family was revoked
        await using (var victimContext = CreateDbContext())
        {
            var victimSut = CreateAuthenticationService(victimContext);
            var victimRes = await victimSut.RefreshTokenAsync(rotatedTokens.RefreshToken);
            Assert.False(victimRes.IsSuccess);
        }
    }

    [Fact]
    public async Task RefreshTokenAsync_ConcurrentRotation_OneSucceedsAndSecondDetectsReplay()
    {
        var email = "concurrent-refresh@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password);
        }

        AuthTokenResult initialTokens;
        await using (var loginContext = CreateDbContext())
        {
            var loginSut = CreateAuthenticationService(loginContext);
            var loginRes = await loginSut.LoginAsync(email, password);
            initialTokens = loginRes.Tokens!;
        }

        // Execute two concurrent refresh calls using distinct DbContext instances
        await using var ctx1 = CreateDbContext();
        await using var ctx2 = CreateDbContext();
        var sut1 = CreateAuthenticationService(ctx1);
        var sut2 = CreateAuthenticationService(ctx2);

        var task1 = sut1.RefreshTokenAsync(initialTokens.RefreshToken, "192.168.1.1");
        var task2 = sut2.RefreshTokenAsync(initialTokens.RefreshToken, "192.168.1.2");

        var results = await Task.WhenAll(task1, task2);

        var successes = results.Count(r => r.IsSuccess);
        var replays = results.Count(r => r.IsReplayDetected);

        Assert.Equal(1, successes);
        Assert.Equal(1, replays);
    }

    // =========================================================================
    // 4. LOGOUT WORKFLOW TESTS
    // =========================================================================

    [Fact]
    public async Task LogoutAsync_ValidSession_RevokesSessionAndActiveRefreshTokensIdempotently()
    {
        var email = "logout-test@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password);
        }

        AuthTokenResult tokens;
        Guid userId;
        await using (var loginContext = CreateDbContext())
        {
            var loginSut = CreateAuthenticationService(loginContext);
            var loginRes = await loginSut.LoginAsync(email, password);
            tokens = loginRes.Tokens!;

            var user = await loginContext.Users.SingleAsync(u => u.Email == email);
            userId = user.Id;
        }

        await using var logoutContext = CreateDbContext();
        var sut = CreateAuthenticationService(logoutContext);

        // 1. Initial logout
        var logoutResult = await sut.LogoutAsync(tokens.SessionId, userId, "10.0.0.5");
        Assert.True(logoutResult.IsSuccess);

        await using (var verifyContext = CreateDbContext())
        {
            var session = await verifyContext.UserSessions
                .SingleAsync(s => s.Id == tokens.SessionId);

            Assert.True(session.IsRevoked);
            Assert.Equal(SessionRevocationReason.UserLogout, session.RevocationReason);

            var sessionTokens = await verifyContext.RefreshTokens
                .Where(t => t.SessionId == session.Id)
                .ToListAsync();

            Assert.All(sessionTokens, t => Assert.True(t.IsRevoked));

            var logoutAudit = await verifyContext.SecurityAuditEvents
                .SingleOrDefaultAsync(e => e.EventType == SecurityAuditEventType.SessionRevoked && e.SessionId == session.Id);
            Assert.NotNull(logoutAudit);
            Assert.Equal("10.0.0.5", logoutAudit.ClientIp);
        }

        // 2. Second logout: idempotent success
        var secondLogoutResult = await sut.LogoutAsync(tokens.SessionId, userId, "10.0.0.5");
        Assert.True(secondLogoutResult.IsSuccess);
    }

    [Fact]
    public async Task LogoutAsync_CallerMismatch_ReturnsFailure()
    {
        var email = "logout-mismatch@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password);
        }

        AuthTokenResult tokens;
        await using (var loginContext = CreateDbContext())
        {
            var loginSut = CreateAuthenticationService(loginContext);
            var loginRes = await loginSut.LoginAsync(email, password);
            tokens = loginRes.Tokens!;
        }

        await using var logoutContext = CreateDbContext();
        var sut = CreateAuthenticationService(logoutContext);

        // Supply a different user ID
        var wrongUserId = Guid.NewGuid();
        var result = await sut.LogoutAsync(tokens.SessionId, wrongUserId, "10.0.0.9");

        Assert.False(result.IsSuccess);
        Assert.Contains("belongs to another identity", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // 5. PASSWORD MUTATION WORKFLOW TESTS
    // =========================================================================

    [Fact]
    public async Task ChangePasswordAsync_ValidCredentials_RotatesSecurityStampAndRevokesAllSessions()
    {
        var email = "pwd-change@example.com";
        var oldPassword = "OldPassword123!";
        var newPassword = "NewSecurePassword456!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, oldPassword);
        }

        User user;
        AuthTokenResult session1Tokens;
        AuthTokenResult session2Tokens;

        await using (var loginContext = CreateDbContext())
        {
            var loginSut = CreateAuthenticationService(loginContext);
            var res1 = await loginSut.LoginAsync(email, oldPassword);
            var res2 = await loginSut.LoginAsync(email, oldPassword);
            session1Tokens = res1.Tokens!;
            session2Tokens = res2.Tokens!;

            user = await loginContext.Users.SingleAsync(u => u.Email == email);
        }

        var oldSecurityStamp = user.SecurityStamp;

        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        await using var changeContext = CreateDbContext();
        var sut = CreateAuthenticationService(changeContext, memoryCache);

        var result = await sut.ChangePasswordAsync(user.Id, oldPassword, newPassword, "172.16.0.10");

        Assert.True(result.IsSuccess);

        // Verify user stamp rotated and sessions revoked
        await using var verifyContext = CreateDbContext();
        var updatedUser = await verifyContext.Users.SingleAsync(u => u.Id == user.Id);

        Assert.NotEqual(oldSecurityStamp, updatedUser.SecurityStamp);
        Assert.True(updatedUser.Version > user.Version);

        var userSessions = await verifyContext.UserSessions
            .Where(s => s.UserId == user.Id)
            .ToListAsync();

        Assert.NotEmpty(userSessions);
        Assert.All(userSessions, s =>
        {
            Assert.True(s.IsRevoked);
            Assert.Equal(SessionRevocationReason.PasswordChanged, s.RevocationReason);
        });

        var userTokens = await verifyContext.RefreshTokens
            .Where(t => userSessions.Select(s => s.Id).Contains(t.SessionId))
            .ToListAsync();

        Assert.All(userTokens, t => Assert.True(t.IsRevoked));

        var changeAudit = await verifyContext.SecurityAuditEvents
            .SingleOrDefaultAsync(e => e.EventType == SecurityAuditEventType.PasswordChanged && e.UserId == user.Id);
        Assert.NotNull(changeAudit);
        Assert.Equal("172.16.0.10", changeAudit.ClientIp);

        // Verify login with old password fails
        await using (var oldLoginCtx = CreateDbContext())
        {
            var oldLoginSut = CreateAuthenticationService(oldLoginCtx);
            var failRes = await oldLoginSut.LoginAsync(email, oldPassword);
            Assert.False(failRes.IsSuccess);
        }

        // Verify login with new password succeeds
        await using (var newLoginCtx = CreateDbContext())
        {
            var newLoginSut = CreateAuthenticationService(newLoginCtx);
            var successRes = await newLoginSut.LoginAsync(email, newPassword);
            Assert.True(successRes.IsSuccess);
        }
    }

    [Fact]
    public async Task AuthorizedResetPasswordAsync_RotatesSecurityStampAndRevokesAllSessions()
    {
        var email = "pwd-reset@example.com";
        var oldPassword = "InitialPassword123!";
        var resetPassword = "ResetPassword999!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, oldPassword);
        }

        User user;
        AuthTokenResult sessionTokens;
        await using (var loginContext = CreateDbContext())
        {
            var loginSut = CreateAuthenticationService(loginContext);
            var res = await loginSut.LoginAsync(email, oldPassword);
            sessionTokens = res.Tokens!;
            user = await loginContext.Users.SingleAsync(u => u.Email == email);
        }

        var oldStamp = user.SecurityStamp;

        await using var resetContext = CreateDbContext();
        var sut = CreateAuthenticationService(resetContext);

        var result = await sut.AuthorizedResetPasswordAsync(user.Id, resetPassword, "10.10.10.10");

        Assert.True(result.IsSuccess);

        await using var verifyContext = CreateDbContext();
        var updatedUser = await verifyContext.Users.SingleAsync(u => u.Id == user.Id);

        Assert.NotEqual(oldStamp, updatedUser.SecurityStamp);

        var sessions = await verifyContext.UserSessions
            .Where(s => s.UserId == user.Id)
            .ToListAsync();

        Assert.All(sessions, s => Assert.True(s.IsRevoked));

        var resetAudit = await verifyContext.SecurityAuditEvents
            .SingleOrDefaultAsync(e => e.EventType == SecurityAuditEventType.PasswordChanged && e.UserId == user.Id);
        Assert.NotNull(resetAudit);
        Assert.Equal("10.10.10.10", resetAudit.ClientIp);
    }

    // =========================================================================
    // 6. GENUINE CONCURRENCY & REHASH REMEDIATION TESTS
    // =========================================================================

    [Fact]
    public async Task RegisterAsync_ConcurrentRegistrationForSameEmail_ResultsInExactlyOneUserAndGenericResponses()
    {
        var email1 = "concurrent-reg@example.com";
        var email2 = "CONCURRENT-REG@EXAMPLE.COM";
        var password = "SecurePassword123!";

        await using var ctx1 = CreateDbContext();
        await using var ctx2 = CreateDbContext();
        var sut1 = CreateAuthenticationService(ctx1);
        var sut2 = CreateAuthenticationService(ctx2);

        var task1 = sut1.RegisterAsync(email1, password, "192.168.1.1");
        var task2 = sut2.RegisterAsync(email2, password, "192.168.1.2");

        var results = await Task.WhenAll(task1, task2);

        Assert.All(results, r =>
        {
            Assert.True(r.IsSuccess);
            Assert.Equal(RegistrationResult.DefaultGenericMessage, r.Message);
        });

        await using var verifyContext = CreateDbContext();
        var users = await verifyContext.Users.Where(u => u.Email == "concurrent-reg@example.com").ToListAsync();
        Assert.Single(users);
    }

    [Fact]
    public async Task LoginAsync_ConcurrentFailedLogins_EnforcesLockoutWithoutLostUpdates()
    {
        var email = "concurrent-failed-login@example.com";
        var password = "CorrectPassword123!";

        await using (var regCtx = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regCtx);
            await regSut.RegisterAsync(email, password);
        }

        // Launch 5 concurrent failed logins using separate DbContext instances
        var tasks = Enumerable.Range(1, 5).Select(async i =>
        {
            await using var ctx = CreateDbContext();
            var sut = CreateAuthenticationService(ctx);
            return await sut.LoginAsync(email, $"WrongPassword_{i}!", $"10.0.0.{i}");
        }).ToList();

        var results = await Task.WhenAll(tasks);

        // Row locks serialize failure updates: all 5 are processed and lockout is triggered
        await using var verifyContext = CreateDbContext();
        var user = await verifyContext.Users.SingleAsync(u => u.Email == email);

        // Reaches consecutive threshold (5) and enters 15-minute lockout
        Assert.True(user.IsLockedOut(DateTime.UtcNow));
        Assert.NotNull(user.LockoutEndUtc);

        // At least one result must reflect the locked out state
        Assert.Contains(results, r => r.IsLockedOut);
    }

    [Fact]
    public async Task LoginAsync_WhenRehashNeeded_UpdatesPasswordHashWithoutRotatingSecurityStamp()
    {
        var email = "rehash-success@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password);
        }

        User userBefore;
        await using (var checkContext = CreateDbContext())
        {
            userBefore = await checkContext.Users.SingleAsync(u => u.Email == email);
        }

        var oldHash = userBefore.PasswordHash;
        var originalStamp = userBefore.SecurityStamp;
        var oldVersion = userBefore.Version;

        var hasher = new PasswordHasher<User>();
        var basePwdService = new PasswordSecurityService(hasher);
        var rehashPwdService = new RehashTriggeringPasswordSecurityService(basePwdService);

        await using var loginContext = CreateDbContext();
        var sut = CreateAuthenticationService(loginContext, customPasswordSecurityService: rehashPwdService);

        var result = await sut.LoginAsync(email, password, "10.0.0.1");

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Tokens);

        await using var verifyContext = CreateDbContext();
        var userAfter = await verifyContext.Users.SingleAsync(u => u.Email == email);

        // Password hash updated
        Assert.NotEqual(oldHash, userAfter.PasswordHash);
        // Version incremented
        Assert.True(userAfter.Version > oldVersion);
        // Security stamp preserved (NOT rotated!)
        Assert.Equal(originalStamp, userAfter.SecurityStamp);
    }

    [Fact]
    public async Task LoginAsync_WhenRehashNeeded_StaleSnapshotAbortsAndDoesNotApplyRehash()
    {
        var email = "rehash-stale@example.com";
        var password = "SecurePassword123!";

        await using (var regContext = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regContext);
            await regSut.RegisterAsync(email, password);
        }

        var hasher = new PasswordHasher<User>();
        var basePwdService = new PasswordSecurityService(hasher);

        // Mutates user concurrently before lock acquisition to simulate stale snapshot race
        var interceptingPwdService = new InterceptingRehashPasswordSecurityService(basePwdService, async () =>
        {
            await using var mutateCtx = CreateDbContext();
            var userToMutate = await mutateCtx.Users.SingleAsync(u => u.Email == email);
            userToMutate.UpdatePassword("NewInterveningPasswordHash999!", DateTime.UtcNow);
            await mutateCtx.SaveChangesAsync();
        });

        await using var loginContext = CreateDbContext();
        var sut = CreateAuthenticationService(loginContext, customPasswordSecurityService: interceptingPwdService);

        var result = await sut.LoginAsync(email, password);

        // Snapshot revalidation must detect that version/hash changed and abort
        Assert.False(result.IsSuccess);
        Assert.Equal("Invalid email or password.", result.ErrorMessage);

        // Intervening password hash must remain intact
        await using var verifyContext = CreateDbContext();
        var user = await verifyContext.Users.SingleAsync(u => u.Email == email);
        Assert.Equal("NewInterveningPasswordHash999!", user.PasswordHash);
    }

    [Fact]
    public async Task RefreshTokenAsync_ReplayOnAlreadyRevokedSession_PreservesOriginalReasonAndPersistsReplayAudit()
    {
        var email = "replay-already-revoked@example.com";
        var password = "SecurePassword123!";

        await using (var regCtx = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regCtx);
            await regSut.RegisterAsync(email, password);
        }

        AuthTokenResult initialTokens;
        Guid userId;
        await using (var loginCtx = CreateDbContext())
        {
            var loginSut = CreateAuthenticationService(loginCtx);
            var loginRes = await loginSut.LoginAsync(email, password);
            initialTokens = loginRes.Tokens!;
            var user = await loginCtx.Users.SingleAsync(u => u.Email == email);
            userId = user.Id;
        }

        // 1. Normal rotation (initialTokens.RefreshToken is rotated into rotatedTokens)
        AuthTokenResult rotatedTokens;
        await using (var rotCtx = CreateDbContext())
        {
            var rotSut = CreateAuthenticationService(rotCtx);
            var rotRes = await rotSut.RefreshTokenAsync(initialTokens.RefreshToken);
            Assert.True(rotRes.IsSuccess);
            rotatedTokens = rotRes.Tokens!;
        }

        // 2. User logs out: session is revoked with UserLogout
        await using (var logoutCtx = CreateDbContext())
        {
            var logoutSut = CreateAuthenticationService(logoutCtx);
            var logoutRes = await logoutSut.LogoutAsync(initialTokens.SessionId, userId);
            Assert.True(logoutRes.IsSuccess);
        }

        // 3. Attacker replays initialTokens.RefreshToken against the ALREADY REVOKED session
        await using (var replayCtx = CreateDbContext())
        {
            var replaySut = CreateAuthenticationService(replayCtx);
            var replayResult = await replaySut.RefreshTokenAsync(initialTokens.RefreshToken, "10.99.99.99");

            Assert.False(replayResult.IsSuccess);
            Assert.True(replayResult.IsReplayDetected);
        }

        // 4. Verify session STILL has UserLogout as reason (not overwritten) AND replay audit event is committed
        await using (var verifyFinalCtx = CreateDbContext())
        {
            var session = await verifyFinalCtx.UserSessions.SingleAsync(s => s.Id == initialTokens.SessionId);
            Assert.True(session.IsRevoked);
            Assert.Equal(SessionRevocationReason.UserLogout, session.RevocationReason);

            var replayAudit = await verifyFinalCtx.SecurityAuditEvents
                .SingleOrDefaultAsync(e => e.EventType == SecurityAuditEventType.TokenReplayDetected && e.SessionId == session.Id);
            Assert.NotNull(replayAudit);
            Assert.Equal("10.99.99.99", replayAudit.ClientIp);
            Assert.Equal(SecurityAuditMetadata.Actions.SessionRevoked, replayAudit.ActionTaken);
        }
    }

    [Fact]
    public async Task LogoutAsync_ConcurrentLogoutForSameSession_IsSafeIdempotentAndConsistent()
    {
        var email = "concurrent-logout@example.com";
        var password = "SecurePassword123!";

        await using (var regCtx = CreateDbContext())
        {
            var regSut = CreateAuthenticationService(regCtx);
            await regSut.RegisterAsync(email, password);
        }

        AuthTokenResult tokens;
        Guid userId;
        await using (var loginCtx = CreateDbContext())
        {
            var loginSut = CreateAuthenticationService(loginCtx);
            var loginRes = await loginSut.LoginAsync(email, password);
            tokens = loginRes.Tokens!;
            var user = await loginCtx.Users.SingleAsync(u => u.Email == email);
            userId = user.Id;
        }

        // Launch 3 concurrent logouts for the same session
        var tasks = Enumerable.Range(1, 3).Select(async i =>
        {
            await using var ctx = CreateDbContext();
            var sut = CreateAuthenticationService(ctx);
            return await sut.LogoutAsync(tokens.SessionId, userId, $"192.168.1.{i}");
        }).ToList();

        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.True(r.IsSuccess));

        await using var verifyContext = CreateDbContext();
        var session = await verifyContext.UserSessions.SingleAsync(s => s.Id == tokens.SessionId);
        Assert.True(session.IsRevoked);
        Assert.Equal(SessionRevocationReason.UserLogout, session.RevocationReason);

        var activeTokens = await verifyContext.RefreshTokens
            .Where(t => t.SessionId == session.Id && t.RevokedAtUtc == null)
            .ToListAsync();
        Assert.Empty(activeTokens);
    }

    private sealed class RehashTriggeringPasswordSecurityService : IPasswordSecurityService
    {
        private readonly IPasswordSecurityService _inner;
        public RehashTriggeringPasswordSecurityService(IPasswordSecurityService inner) => _inner = inner;

        public string DummyHash => _inner.DummyHash;

        public string HashPassword(User user, string password) => _inner.HashPassword(user, password);
        public PasswordVerificationResult VerifyHashedPassword(User user, string hashedPassword, string providedPassword)
            => PasswordVerificationResult.SuccessRehashNeeded;
        public bool NeedsRehash(PasswordVerificationResult result) => true;
        public void VerifyDummyPassword(string providedPassword) => _inner.VerifyDummyPassword(providedPassword);
    }

    private sealed class InterceptingRehashPasswordSecurityService : IPasswordSecurityService
    {
        private readonly IPasswordSecurityService _inner;
        private readonly Func<Task> _onPrecomputeRehash;

        public InterceptingRehashPasswordSecurityService(IPasswordSecurityService inner, Func<Task> onPrecomputeRehash)
        {
            _inner = inner;
            _onPrecomputeRehash = onPrecomputeRehash;
        }

        public string DummyHash => _inner.DummyHash;

        public string HashPassword(User user, string password)
        {
            _onPrecomputeRehash().GetAwaiter().GetResult();
            return _inner.HashPassword(user, password);
        }

        public PasswordVerificationResult VerifyHashedPassword(User user, string hashedPassword, string providedPassword)
            => PasswordVerificationResult.SuccessRehashNeeded;
        public bool NeedsRehash(PasswordVerificationResult result) => true;
        public void VerifyDummyPassword(string providedPassword) => _inner.VerifyDummyPassword(providedPassword);
    }
}
