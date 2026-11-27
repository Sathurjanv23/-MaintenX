namespace MaintenX.IntegrationTests;

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Configuration;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

/// <summary>
/// PostgreSQL 16 integration tests for <see cref="PlatformGrantResolver"/>.
/// Covers authoritative DB verification (account, session, security stamp, grant),
/// server-controlled Bearer authentication provenance, real ASP.NET Core JwtBearerHandler
/// pipeline validation, and grant/account/session freshness using the same signed JWT.
/// </summary>
public class PlatformGrantResolverIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public PlatformGrantResolverIntegrationTests()
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

        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("ConnectionStrings:DefaultConnection", _isolatedConnectionString);

            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:DefaultConnection"] = _isolatedConnectionString,
                    ["TrustedProxies:KnownProxies:0"] = "127.0.0.1",
                    ["TrustedProxies:KnownProxies:1"] = "::1",
                    ["TrustedProxies:ForwardLimit"] = "1"
                });
            });

            builder.ConfigureServices(services =>
            {
                services.AddTransient<IStartupFilter, TestOnlyPlatformResolverEndpointFilter>();
            });
        });
    }

    public async Task DisposeAsync()
    {
        _factory.Dispose();
        if (!string.IsNullOrWhiteSpace(_databaseName))
        {
            await TestDatabaseGuard.DropDatabaseSafelyAsync(_databaseName, _adminConnectionString);
        }
    }

    private MaintenXDbContext CreateDbContext(ITenantContextAccessor? tenantContextAccessor = null)
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return tenantContextAccessor is null
            ? new MaintenXDbContext(options)
            : new MaintenXDbContext(options, tenantContextAccessor);
    }

    private static PlatformGrantResolver CreateResolver(
        MaintenXDbContext db,
        ClaimsPrincipal? authenticatedPrincipal,
        TimeProvider? timeProvider = null)
    {
        var httpContext = new DefaultHttpContext();
        var authResult = authenticatedPrincipal is null
            ? AuthenticateResult.NoResult()
            : AuthenticateResult.Success(new AuthenticationTicket(authenticatedPrincipal, JwtBearerDefaults.AuthenticationScheme));

        return new PlatformGrantResolver(
            new HttpContextAccessor { HttpContext = httpContext },
            new StubAuthenticationService(authResult),
            db,
            timeProvider ?? TimeProvider.System,
            NullLogger<PlatformGrantResolver>.Instance);
    }

    private static ClaimsPrincipal CreatePrincipal(User user, UserSession session) =>
        new(new ClaimsIdentity(
            new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Sid, session.Id.ToString()),
                new Claim("sst", user.SecurityStamp)
            },
            JwtBearerDefaults.AuthenticationScheme));

    // =========================================================================
    // 1. Direct Authoritative DB & Scope Matrix
    // =========================================================================

    [Fact]
    public async Task ValidPlatformAdmin_AllowsAll4PlatformPermissions_AndDeniesAll10TenantPermissions()
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"admin.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var actor = User.Create($"actor.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(1));
        var grant = PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, actor.Id, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(user, actor);
            seedDb.UserSessions.Add(session);
            seedDb.PlatformRoleGrants.Add(grant);
            await seedDb.SaveChangesAsync();
        }

        var principal = CreatePrincipal(user, session);
        using var evalDb = CreateDbContext();
        var resolver = CreateResolver(evalDb, principal);

        foreach (var perm in PermissionCatalog.PlatformPermissions)
        {
            var result = await resolver.ResolveAsync(perm.Key);
            Assert.True(result.IsAllowed, $"Expected {perm.Key.Value} to be allowed.");
            Assert.Equal(user.Id, result.UserId);
            Assert.Equal(grant.Id, result.GrantId);
            Assert.Equal(PlatformRole.PlatformAdministrator, result.Role);
        }

        foreach (var tenantPerm in PermissionCatalog.TenantPermissions)
        {
            var result = await resolver.ResolveAsync(tenantPerm.Key);
            Assert.False(result.IsAllowed, $"Expected {tenantPerm.Key.Value} to be denied.");
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData(TenantMembershipRole.Owner)]
    [InlineData(TenantMembershipRole.Administrator)]
    [InlineData(TenantMembershipRole.Member)]
    public async Task OrdinaryOrTenantScopedUsersWithoutPlatformGrant_AreDenied(TenantMembershipRole? tenantRole)
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"tenantonly.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(1));

        using (var seedDb = CreateDbContext())
        {
            seedDb.CreatePrivilegedTenantBypassScope("seed-tenant-only");
            seedDb.Users.Add(user);
            seedDb.UserSessions.Add(session);

            if (tenantRole.HasValue)
            {
                var tenant = Tenant.Create($"org-{Guid.NewGuid():N}"[..16], "Tenant Org", TenantStatus.Active);
                seedDb.Tenants.Add(tenant);
                seedDb.TenantMemberships.Add(TenantMembership.Create(tenant.Id, user.Id, tenantRole.Value));
            }

            await seedDb.SaveChangesAsync();
        }

        using var evalDb = CreateDbContext();
        var result = await CreateResolver(evalDb, CreatePrincipal(user, session)).ResolveAsync(PermissionCatalog.Platform.TenantsRead);
        Assert.False(result.IsAllowed);
        Assert.Equal("NoActivePlatformGrant", result.DenialReason);
    }

    [Fact]
    public async Task RevokedGrant_AndAnotherUsersGrant_AreDenied()
    {
        var now = DateTime.UtcNow;
        var userA = User.Create($"usera.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var userB = User.Create($"userb.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var sessionA = UserSession.Create(userA.Id, now, TimeSpan.FromHours(1));

        var revokedGrantA = PlatformRoleGrant.Create(userA.Id, PlatformRole.PlatformAdministrator, userB.Id, now);
        revokedGrantA.Revoke(userB.Id, "Revoked prior to check", now.AddMinutes(1));
        var activeGrantB = PlatformRoleGrant.Create(userB.Id, PlatformRole.PlatformAdministrator, userA.Id, now);

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(userA, userB);
            seedDb.UserSessions.Add(sessionA);
            seedDb.PlatformRoleGrants.AddRange(revokedGrantA, activeGrantB);
            await seedDb.SaveChangesAsync();
        }

        using var evalDb = CreateDbContext();
        var result = await CreateResolver(evalDb, CreatePrincipal(userA, sessionA)).ResolveAsync(PermissionCatalog.Platform.TenantsRead);
        Assert.False(result.IsAllowed);
        Assert.Equal("NoActivePlatformGrant", result.DenialReason);
    }

    [Fact]
    public async Task InvalidAccount_InvalidSession_AndSecurityStampMismatch_AreDenied()
    {
        var now = DateTime.UtcNow;
        var suspendedUser = User.Create($"susp.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        suspendedUser.Suspend(now);
        var validUser = User.Create($"valid.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);

        var suspendedSession = UserSession.Create(suspendedUser.Id, now, TimeSpan.FromHours(1));
        var validSession = UserSession.Create(validUser.Id, now, TimeSpan.FromHours(1));
        var wrongUserSession = UserSession.Create(suspendedUser.Id, now, TimeSpan.FromHours(1));
        var revokedSession = UserSession.Create(validUser.Id, now, TimeSpan.FromHours(1));
        revokedSession.Revoke(SessionRevocationReason.UserLogout, now.AddMinutes(1));

        using (var seedDb = CreateDbContext())
        {
            seedDb.Users.AddRange(suspendedUser, validUser);
            seedDb.UserSessions.AddRange(suspendedSession, validSession, wrongUserSession, revokedSession);
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(suspendedUser.Id, PlatformRole.PlatformAdministrator, validUser.Id, now));
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(validUser.Id, PlatformRole.PlatformAdministrator, validUser.Id, now));
            await seedDb.SaveChangesAsync();
        }

        using var evalDb = CreateDbContext();
        var perm = PermissionCatalog.Platform.TenantsRead;

        Assert.Equal("IneligibleAccountOrSecurityStampMismatch",
            (await CreateResolver(evalDb, CreatePrincipal(suspendedUser, suspendedSession)).ResolveAsync(perm)).DenialReason);

        var wrongStampPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, validUser.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Sid, validSession.Id.ToString()),
            new Claim("sst", "stale-or-forged-stamp")
        }, JwtBearerDefaults.AuthenticationScheme));
        Assert.Equal("IneligibleAccountOrSecurityStampMismatch",
            (await CreateResolver(evalDb, wrongStampPrincipal).ResolveAsync(perm)).DenialReason);

        Assert.Equal("InvalidOrExpiredSession",
            (await CreateResolver(evalDb, CreatePrincipal(validUser, wrongUserSession)).ResolveAsync(perm)).DenialReason);

        Assert.Equal("InvalidOrExpiredSession",
            (await CreateResolver(evalDb, CreatePrincipal(validUser, revokedSession)).ResolveAsync(perm)).DenialReason);
    }

    [Fact]
    public async Task GlobalScope_ConsistentAcrossNoTenantTenantAAndTenantB()
    {
        var now = DateTime.UtcNow;
        var user = User.Create($"scope.{Guid.NewGuid():N}@maintenx.internal", "hash", UserStatus.Active, now);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(1));
        var tenantA = Tenant.Create($"sa-{Guid.NewGuid():N}"[..16], "Tenant A", TenantStatus.Active);
        var tenantB = Tenant.Create($"sb-{Guid.NewGuid():N}"[..16], "Tenant B", TenantStatus.Active);
        var membershipA = TenantMembership.Create(tenantA.Id, user.Id, TenantMembershipRole.Member);
        var membershipB = TenantMembership.Create(tenantB.Id, user.Id, TenantMembershipRole.Owner);

        using (var seedDb = CreateDbContext())
        {
            seedDb.CreatePrivilegedTenantBypassScope("seed-global-resolver");
            seedDb.Users.Add(user);
            seedDb.UserSessions.Add(session);
            seedDb.Tenants.AddRange(tenantA, tenantB);
            seedDb.TenantMemberships.AddRange(membershipA, membershipB);
            seedDb.PlatformRoleGrants.Add(PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, user.Id, now));
            await seedDb.SaveChangesAsync();
        }

        var principal = CreatePrincipal(user, session);

        using (var dbNone = CreateDbContext(new TenantContextAccessor()))
        {
            Assert.True((await CreateResolver(dbNone, principal).ResolveAsync(PermissionCatalog.Platform.TenantsRead)).IsAllowed);
        }

        var accessorA = new TenantContextAccessor();
        accessorA.SetContext(new TenantContext(
            tenantA.Id, tenantA.Slug, tenantA.DisplayName, user.Id, membershipA.Id,
            TenantMembershipRole.Member, TenantMembershipStatus.Active, now));
        using (var dbA = CreateDbContext(accessorA))
        {
            Assert.True((await CreateResolver(dbA, principal).ResolveAsync(PermissionCatalog.Platform.TenantsRead)).IsAllowed);
        }

        var accessorB = new TenantContextAccessor();
        accessorB.SetContext(new TenantContext(
            tenantB.Id, tenantB.Slug, tenantB.DisplayName, user.Id, membershipB.Id,
            TenantMembershipRole.Owner, TenantMembershipStatus.Active, now));
        using (var dbB = CreateDbContext(accessorB))
        {
            Assert.True((await CreateResolver(dbB, principal).ResolveAsync(PermissionCatalog.Platform.TenantsRead)).IsAllowed);
        }
    }

    // =========================================================================
    // 2. Real ASP.NET Core JwtBearerHandler Pipeline & Grant Freshness Tests
    // =========================================================================

    [Fact]
    public async Task RealJwtPipeline_ValidTokenAllowed_InvalidSignatureUnsignedExpiredIssuerAudienceMalformedUntrustedDenied()
    {
        var client = _factory.CreateClient();
        var email = $"jwt_admin_{Guid.NewGuid():N}@maintenx.dev";
        const string password = "SecurePassword123!";

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password))).StatusCode);
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        Guid userId;
        Guid sessionId;
        string securityStamp;
        using (var db = CreateDbContext())
        {
            var user = await db.Users.SingleAsync(u => u.Email == email);
            var session = await db.UserSessions.SingleAsync(s => s.UserId == user.Id && s.RevokedAtUtc == null);
            userId = user.Id;
            sessionId = session.Id;
            securityStamp = user.SecurityStamp;

            db.PlatformRoleGrants.Add(PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, user.Id, DateTime.UtcNow));
            await db.SaveChangesAsync();
        }

        var jwtOpts = _factory.Services.GetRequiredService<IOptions<JwtOptions>>().Value;
        var validSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(jwtOpts.SigningKey));
        var wrongSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("wrong-signing-key-that-must-be-rejected-123456"));

        string BuildToken(SigningCredentials? creds, string issuer, string audience, DateTime expiresUtc)
        {
            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                    new Claim(JwtRegisteredClaimNames.Sid, sessionId.ToString()),
                    new Claim("sst", securityStamp)
                }),
                Issuer = issuer,
                Audience = audience,
                NotBefore = expiresUtc.AddMinutes(-15),
                Expires = expiresUtc,
                SigningCredentials = creds
            };
            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(descriptor));
        }

        async Task<(HttpStatusCode Status, bool IsAllowed, string? Reason)> ProbeAsync(string? authHeader, bool addForgedHeader = false)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, "/__test/platform-resolve?perm=platform.tenants.read");
            if (authHeader is not null)
            {
                req.Headers.TryAddWithoutValidation("Authorization", authHeader);
            }
            if (addForgedHeader)
            {
                req.Headers.Add("X-Platform-Admin", "true");
            }

            using var resp = await client.SendAsync(req);
            var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
            return (
                resp.StatusCode,
                json.GetProperty("isAllowed").GetBoolean(),
                json.TryGetProperty("denialReason", out var dr) && dr.ValueKind != JsonValueKind.Null ? dr.GetString() : null);
        }

        // Valid signed JWT from real login -> Allowed
        var validRes = await ProbeAsync($"Bearer {loginBody!.AccessToken}");
        Assert.Equal(HttpStatusCode.OK, validRes.Status);
        Assert.True(validRes.IsAllowed);

        // Missing token -> Denied
        var missingRes = await ProbeAsync(null, addForgedHeader: true);
        Assert.Equal(HttpStatusCode.Forbidden, missingRes.Status);
        Assert.False(missingRes.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", missingRes.Reason);

        // Malformed token -> Denied
        var malformedRes = await ProbeAsync("Bearer not.a.valid.jwt");
        Assert.Equal(HttpStatusCode.Forbidden, malformedRes.Status);
        Assert.False(malformedRes.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", malformedRes.Reason);

        // Untrusted scheme -> Denied
        var untrustedSchemeRes = await ProbeAsync($"CustomScheme {loginBody.AccessToken}", addForgedHeader: true);
        Assert.Equal(HttpStatusCode.Forbidden, untrustedSchemeRes.Status);
        Assert.False(untrustedSchemeRes.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", untrustedSchemeRes.Reason);

        // Invalid signature -> Denied
        var badSigToken = BuildToken(new SigningCredentials(wrongSigningKey, SecurityAlgorithms.HmacSha256), jwtOpts.Issuer, jwtOpts.Audience, DateTime.UtcNow.AddMinutes(10));
        var badSigRes = await ProbeAsync($"Bearer {badSigToken}");
        Assert.Equal(HttpStatusCode.Forbidden, badSigRes.Status);
        Assert.False(badSigRes.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", badSigRes.Reason);

        // Unsigned (alg: none) -> Denied
        var unsignedToken = BuildToken(null, jwtOpts.Issuer, jwtOpts.Audience, DateTime.UtcNow.AddMinutes(10));
        var unsignedRes = await ProbeAsync($"Bearer {unsignedToken}");
        Assert.Equal(HttpStatusCode.Forbidden, unsignedRes.Status);
        Assert.False(unsignedRes.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", unsignedRes.Reason);

        // Expired beyond clock skew -> Denied
        var expiredToken = BuildToken(new SigningCredentials(validSigningKey, SecurityAlgorithms.HmacSha256), jwtOpts.Issuer, jwtOpts.Audience, DateTime.UtcNow.AddMinutes(-1));
        var expiredRes = await ProbeAsync($"Bearer {expiredToken}");
        Assert.Equal(HttpStatusCode.Forbidden, expiredRes.Status);
        Assert.False(expiredRes.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", expiredRes.Reason);

        // Invalid issuer -> Denied
        var badIssuerToken = BuildToken(new SigningCredentials(validSigningKey, SecurityAlgorithms.HmacSha256), "https://untrusted-issuer.invalid", jwtOpts.Audience, DateTime.UtcNow.AddMinutes(10));
        var badIssuerRes = await ProbeAsync($"Bearer {badIssuerToken}");
        Assert.Equal(HttpStatusCode.Forbidden, badIssuerRes.Status);
        Assert.False(badIssuerRes.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", badIssuerRes.Reason);

        // Invalid audience -> Denied
        var badAudienceToken = BuildToken(new SigningCredentials(validSigningKey, SecurityAlgorithms.HmacSha256), jwtOpts.Issuer, "untrusted-audience", DateTime.UtcNow.AddMinutes(10));
        var badAudienceRes = await ProbeAsync($"Bearer {badAudienceToken}");
        Assert.Equal(HttpStatusCode.Forbidden, badAudienceRes.Status);
        Assert.False(badAudienceRes.IsAllowed);
        Assert.Equal("UnauthenticatedBearerContext", badAudienceRes.Reason);
    }

    [Fact]
    public async Task RealJwtPipeline_SameSignedTokenDeniedImmediatelyAfterGrantRevokeAccountSuspendStampRotateOrSessionRevoke()
    {
        var client = _factory.CreateClient();
        var email = $"jwt_fresh_{Guid.NewGuid():N}@maintenx.dev";
        const string password = "SecurePassword123!";

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password))).StatusCode);
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        var loginBody = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(loginBody);

        Guid userId;
        Guid grantId;
        using (var db = CreateDbContext())
        {
            var user = await db.Users.SingleAsync(u => u.Email == email);
            userId = user.Id;
            var grant = PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, user.Id, DateTime.UtcNow);
            grantId = grant.Id;
            db.PlatformRoleGrants.Add(grant);
            await db.SaveChangesAsync();
        }

        async Task<(bool IsAllowed, string? Reason)> CallWithTokenAsync(string token)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, "/__test/platform-resolve?perm=platform.tenants.activate");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await client.SendAsync(req);
            var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
            return (
                json.GetProperty("isAllowed").GetBoolean(),
                json.TryGetProperty("denialReason", out var dr) && dr.ValueKind != JsonValueKind.Null ? dr.GetString() : null);
        }

        // 1. Same valid signed JWT initially allowed
        var r1 = await CallWithTokenAsync(loginBody!.AccessToken);
        Assert.True(r1.IsAllowed);

        // 2. Revoke grant in separate DbContext -> same JWT denied immediately
        using (var revokeDb = CreateDbContext())
        {
            var g = await revokeDb.PlatformRoleGrants.SingleAsync(x => x.Id == grantId);
            g.Revoke(userId, "Revoked during real JWT freshness test", DateTime.UtcNow.AddSeconds(1));
            await revokeDb.SaveChangesAsync();
        }

        var r2 = await CallWithTokenAsync(loginBody.AccessToken);
        Assert.False(r2.IsAllowed);
        Assert.Equal("NoActivePlatformGrant", r2.Reason);

        // 3. Re-grant active, then suspend account -> same JWT denied
        using (var db = CreateDbContext())
        {
            db.PlatformRoleGrants.Add(PlatformRoleGrant.Create(userId, PlatformRole.PlatformAdministrator, userId, DateTime.UtcNow));
            var u = await db.Users.SingleAsync(x => x.Id == userId);
            u.Suspend(DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        var r3 = await CallWithTokenAsync(loginBody.AccessToken);
        Assert.False(r3.IsAllowed);
        Assert.Equal("IneligibleAccountOrSecurityStampMismatch", r3.Reason);

        // 4. Reactivate + rotate security stamp -> same JWT denied
        using (var db = CreateDbContext())
        {
            var u = await db.Users.SingleAsync(x => x.Id == userId);
            u.Reactivate(DateTime.UtcNow);
            u.RotateSecurityStamp(DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        var r4 = await CallWithTokenAsync(loginBody.AccessToken);
        Assert.False(r4.IsAllowed);
        Assert.Equal("IneligibleAccountOrSecurityStampMismatch", r4.Reason);

        // 5. Login for fresh JWT, then revoke session -> fresh JWT denied immediately
        var login2 = await (await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password)))
            .Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(login2);

        using (var db = CreateDbContext())
        {
            var activeSession = await db.UserSessions
                .Where(s => s.UserId == userId && s.RevokedAtUtc == null)
                .OrderByDescending(s => s.CreatedAtUtc)
                .FirstAsync();
            activeSession.Revoke(SessionRevocationReason.UserLogout, DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        var r5 = await CallWithTokenAsync(login2!.AccessToken);
        Assert.False(r5.IsAllowed);
        Assert.Contains(r5.Reason, new[] { "InvalidOrExpiredSession", "UnauthenticatedBearerContext" });
    }

    private sealed class StubAuthenticationService(AuthenticateResult result) : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(string.Equals(scheme, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal)
                ? result
                : AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }

    /// <summary>
    /// Isolated test-host-only endpoint used exclusively to exercise real JwtBearerHandler -> IPlatformGrantResolver
    /// without adding any production authorization endpoint.
    /// </summary>
    private sealed class TestOnlyPlatformResolverEndpointFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                next(app);
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/__test/platform-resolve", async (
                        HttpContext ctx,
                        IPlatformGrantResolver resolver,
                        CancellationToken ct) =>
                    {
                        var permStr = ctx.Request.Query["perm"].ToString();
                        PermissionKey? perm = PermissionKey.TryParse(permStr, out var parsed) ? parsed : null;
                        var result = await resolver.ResolveAsync(perm, ct);
                        return result.IsAllowed
                            ? Results.Ok(new { result.IsAllowed, result.UserId, result.GrantId, Role = result.Role?.ToString(), result.DenialReason })
                            : Results.Json(new { result.IsAllowed, result.DenialReason }, statusCode: StatusCodes.Status403Forbidden);
                    });
                });
            };
        }
    }
}
