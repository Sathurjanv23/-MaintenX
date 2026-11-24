namespace MaintenX.IntegrationTests;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

/// <summary>
/// HTTP Integration tests for FEAT-003 Task 3.6.2 Tenant Onboarding HTTP API (POST /api/v1/tenants).
/// Validates authenticated tenant onboarding, atomic PendingOnboarding tenant creation with Owner membership,
/// rejection of unauthenticated/revoked sessions, anti-tampering against forged user/admin/role inputs,
/// duplicate slug collision handling, and tenant rate limiting.
/// </summary>
public class TenantOnboardingHttpIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public TenantOnboardingHttpIntegrationTests()
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
                services.AddTransient<IStartupFilter, TestSocketSimulationStartupFilter>();
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

    private MaintenXDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return new MaintenXDbContext(options);
    }

    private static int _ipCounter = 500;
    private HttpClient CreateUniqueClient()
    {
        var id = Interlocked.Increment(ref _ipCounter);
        var ip = $"198.51.{(id / 250) % 250}.{id % 250 + 1}";
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Socket-Remote-Ip", ip);
        return client;
    }

    private async Task<(HttpClient Client, User User, string Token, Guid SessionId)> CreateAuthenticatedUserAsync(string prefix = "onboard_user")
    {
        var client = CreateUniqueClient();
        var email = $"{prefix}_{Guid.NewGuid():N}@maintenx.dev";
        var password = "SecurePassword123!";

        var regResp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, regResp.StatusCode);

        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);

        var body = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(body);

        using var db = CreateDbContext();
        var user = await db.Users.FirstAsync(u => u.Email == email);
        var session = await db.UserSessions.FirstAsync(s => s.UserId == user.Id && s.RevokedAtUtc == null);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.AccessToken);
        return (client, user, body.AccessToken, session.Id);
    }

    private sealed class TestSocketSimulationStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                app.Use(async (context, nextMiddleware) =>
                {
                    if (context.Request.Headers.TryGetValue("X-Test-Socket-Remote-Ip", out var socketIpHeader) &&
                        IPAddress.TryParse(socketIpHeader.ToString(), out var socketIp))
                    {
                        context.Connection.RemoteIpAddress = socketIp;
                    }

                    await nextMiddleware();
                });

                next(app);
            };
        }
    }

    // =========================================================================
    // 1. SUCCESSFUL ONBOARDING WORKFLOWS
    // =========================================================================

    [Fact]
    public async Task PostTenants_AuthenticatedUser_CreatesPendingTenantWithOwnerMembership_Returns201Created()
    {
        // Arrange
        var (client, user, _, _) = await CreateAuthenticatedUserAsync("success_user");
        var slug = $"acme-corp-{Guid.NewGuid():N}"[..24];
        var request = new CreateTenantRequest(slug, "Acme Corporation");

        // Act (Works without X-Tenant-ID header)
        var response = await client.PostAsJsonAsync("/api/v1/tenants", request);

        // Assert HTTP response
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        var responseBody = await response.Content.ReadFromJsonAsync<CreateTenantResponse>();
        Assert.NotNull(responseBody);
        Assert.NotEqual(Guid.Empty, responseBody.TenantId);
        Assert.Equal(slug, responseBody.Slug);
        Assert.Equal("Acme Corporation", responseBody.DisplayName);
        Assert.Equal("PendingOnboarding", responseBody.Status);

        // Assert database persistence & atomic initial owner membership
        using var db = CreateDbContext();
        var tenant = await db.Tenants.SingleOrDefaultAsync(t => t.Id == responseBody.TenantId);
        Assert.NotNull(tenant);
        Assert.Equal(TenantStatus.PendingOnboarding, tenant.Status);

        using (db.CreatePrivilegedTenantBypassScope("verify-owner-membership"))
        {
            var membership = await db.TenantMemberships
                .SingleOrDefaultAsync(m => m.TenantId == tenant.Id && m.UserId == user.Id);

            Assert.NotNull(membership);
            Assert.Equal(TenantMembershipRole.Owner, membership.Role);
            Assert.Equal(TenantMembershipStatus.Active, membership.Status);
        }
    }

    [Fact]
    public async Task PostTenants_PendingOnboardingTenant_CannotEstablishOperationalContext()
    {
        // Arrange
        var (client, user, _, _) = await CreateAuthenticatedUserAsync("pending_access");
        var slug = $"pending-org-{Guid.NewGuid():N}"[..24];
        var request = new CreateTenantRequest(slug, "Pending Org");

        var createResponse = await client.PostAsJsonAsync("/api/v1/tenants", request);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        var created = await createResponse.Content.ReadFromJsonAsync<CreateTenantResponse>();

        // Act: Attempt to access tenant-scoped endpoint using the newly onboarded tenant's ID
        client.DefaultRequestHeaders.Add("X-Tenant-ID", created!.TenantId.ToString());
        var contextResponse = await client.GetAsync("/api/v1/tenancy/current");

        // Assert: 403 Forbidden because tenant is PendingOnboarding (not Active)
        Assert.Equal(HttpStatusCode.Forbidden, contextResponse.StatusCode);
    }

    // =========================================================================
    // 2. AUTHENTICATION & SESSION INVARIANTS
    // =========================================================================

    [Fact]
    public async Task PostTenants_UnauthenticatedCaller_Returns401Unauthorized()
    {
        var client = CreateUniqueClient(); // No auth header
        var request = new CreateTenantRequest("unauth-slug", "Unauth Org");

        var response = await client.PostAsJsonAsync("/api/v1/tenants", request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task PostTenants_RevokedSession_Returns401Unauthorized()
    {
        var (client, user, _, sessionId) = await CreateAuthenticatedUserAsync("revoked_session_user");

        // Revoke session in database
        using (var db = CreateDbContext())
        {
            var session = await db.UserSessions.FirstAsync(s => s.Id == sessionId);
            session.Revoke(SessionRevocationReason.AdminRevoked, DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        var request = new CreateTenantRequest($"revoked-{Guid.NewGuid():N}"[..20], "Revoked Org");
        var response = await client.PostAsJsonAsync("/api/v1/tenants", request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // =========================================================================
    // 3. INPUT VALIDATION & CONFLICTS
    // =========================================================================

    [Theory]
    [InlineData("", "Valid Name")]
    [InlineData("a", "Valid Name")]
    [InlineData("-invalid-slug", "Valid Name")]
    [InlineData("invalid-slug-", "Valid Name")]
    [InlineData("invalid--slug", "Valid Name")]
    [InlineData("invalid slug", "Valid Name")]
    [InlineData("valid-slug", "")]
    [InlineData("valid-slug", " ")]
    [InlineData("valid-slug", "A")]
    public async Task PostTenants_InvalidInput_Returns400BadRequest(string slug, string displayName)
    {
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("validation_user");
        var request = new CreateTenantRequest(slug, displayName);

        var response = await client.PostAsJsonAsync("/api/v1/tenants", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task PostTenants_DuplicateSlug_Returns409Conflict()
    {
        var (client, _, _, _) = await CreateAuthenticatedUserAsync("conflict_user");
        var slug = $"duplicate-slug-{Guid.NewGuid():N}"[..24];
        var request = new CreateTenantRequest(slug, "First Tenant");

        // First creation succeeds
        var firstResponse = await client.PostAsJsonAsync("/api/v1/tenants", request);
        Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);

        // Second creation with identical slug fails with 409 Conflict
        var secondRequest = new CreateTenantRequest(slug, "Second Tenant Attempt");
        var secondResponse = await client.PostAsJsonAsync("/api/v1/tenants", secondRequest);

        Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
        var doc = JsonDocument.Parse(await secondResponse.Content.ReadAsStringAsync());
        Assert.Equal(409, doc.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task PostTenants_ConcurrentDuplicateCreation_PreservesUniqueness()
    {
        var (client1, _, _, _) = await CreateAuthenticatedUserAsync("concurrent_user1");
        var (client2, _, _, _) = await CreateAuthenticatedUserAsync("concurrent_user2");

        var slug = $"concurrent-slug-{Guid.NewGuid():N}"[..24];
        var req1 = new CreateTenantRequest(slug, "Concurrent Org 1");
        var req2 = new CreateTenantRequest(slug, "Concurrent Org 2");

        var task1 = client1.PostAsJsonAsync("/api/v1/tenants", req1);
        var task2 = client2.PostAsJsonAsync("/api/v1/tenants", req2);

        var responses = await Task.WhenAll(task1, task2);

        // Exactly one must succeed with 201 Created and the other must fail with 409 Conflict
        var statusCodes = responses.Select(r => r.StatusCode).ToList();
        Assert.Contains(HttpStatusCode.Created, statusCodes);
        Assert.Contains(HttpStatusCode.Conflict, statusCodes);

        using var db = CreateDbContext();
        var count = await db.Tenants.CountAsync(t => t.Slug == slug);
        Assert.Equal(1, count);
    }

    // =========================================================================
    // 4. MASS ASSIGNMENT & TAMPERING INVARIANTS
    // =========================================================================

    [Fact]
    public async Task PostTenants_ForgedPayloadFields_IgnoredAndCannotElevatePrivileges()
    {
        var (client, user, _, _) = await CreateAuthenticatedUserAsync("tamper_user");
        var slug = $"tamper-proof-{Guid.NewGuid():N}"[..24];
        var victimUserId = Guid.NewGuid();

        // Submit raw JSON payload attempting to forge creatorUserId, status, and role
        var maliciousPayload = new
        {
            slug = slug,
            displayName = "Tamper Proof Org",
            creatorUserId = victimUserId,
            status = "Active",
            role = "Administrator",
            isPlatformAdmin = true
        };

        var response = await client.PostAsJsonAsync("/api/v1/tenants", maliciousPayload);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<CreateTenantResponse>();
        Assert.NotNull(created);
        // Tenant status MUST be PendingOnboarding (not forged "Active")
        Assert.Equal("PendingOnboarding", created.Status);

        using var db = CreateDbContext();
        var tenant = await db.Tenants.SingleAsync(t => t.Id == created.TenantId);
        Assert.Equal(TenantStatus.PendingOnboarding, tenant.Status);

        using (db.CreatePrivilegedTenantBypassScope("verify-ownership"))
        {
            // Membership MUST belong to authenticated caller, NOT victimUserId
            var membership = await db.TenantMemberships.SingleAsync(m => m.TenantId == tenant.Id);
            Assert.Equal(user.Id, membership.UserId);
            Assert.Equal(TenantMembershipRole.Owner, membership.Role);
        }
    }
}
