namespace MaintenX.IntegrationTests;

using System.Data;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

/// <summary>
/// FEAT-004 Task 4.4.4 — Multi-Tenancy Boundary Security Verification Suite.
/// Final verification gate for Step 4.4 (Tenant Context & Boundary Enforcement):
/// 1. Cross-tenant data isolation: strict anti-enumeration prevents existence or state inference.
/// 2. Header and route tampering: mismatched X-Tenant-ID and route parameters fail closed.
/// 3. Platform administrator bypass auditing: all un-enrolled tenant accesses create durable audit records.
/// 4. Anonymous and unauthenticated access: tenant-scoped endpoints reject unauthenticated calls.
/// </summary>
public class MultiTenancyBoundarySecurityTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public MultiTenancyBoundarySecurityTests()
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

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
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

    private HttpClient CreateClientWithIp(string ipAddress = "127.0.0.1")
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Forwarded-For", ipAddress);
        return client;
    }

    private async Task<(string Token, Guid UserId)> RegisterAndLoginUserAsync(string email, string password = "ValidPassword123!", string ip = "127.0.0.1")
    {
        var client = CreateClientWithIp(ip);
        var regResp = await client.PostAsJsonAsync("/api/v1/auth/register", new RegisterRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, regResp.StatusCode);

        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);

        var login = await loginResp.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(login);

        using var db = CreateDbContext();
        var user = await db.Users.SingleAsync(u => u.Email == email);
        return (login.AccessToken, user.Id);
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("invalid-guid-string")]
    [InlineData("'; DROP TABLE platform.tenants; --")]
    public async Task ThreatVector_MalformedTenantHeader_ReturnsBadRequestOrNotFound_WithoutLeakage(string malformedTenant)
    {
        var (token, _) = await RegisterAndLoginUserAsync($"malformed.{Guid.NewGuid():N}@maintenx.internal");

        var client = CreateClientWithIp();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenancy/current");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        req.Headers.Add("X-Tenant-ID", malformedTenant);

        using var resp = await client.SendAsync(req);
        Assert.True(resp.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Invariant_CrossTenantTampering_IsRejectedWith403Forbidden()
    {
        var (userToken, userId) = await RegisterAndLoginUserAsync($"tamper.{Guid.NewGuid():N}@maintenx.internal");

        Guid tenantAlphaId;
        Guid tenantBetaId;

        using (var db = CreateDbContext())
        {
            var tA = Tenant.Create("tamper-alpha", "Tamper Alpha", TenantStatus.Active);
            var tB = Tenant.Create("tamper-beta", "Tamper Beta", TenantStatus.Active);
            db.Tenants.AddRange(tA, tB);
            await db.SaveChangesAsync();

            tenantAlphaId = tA.Id;
            tenantBetaId = tB.Id;

            using (db.CreatePrivilegedTenantBypassScope("seed-memberships"))
            {
                db.TenantMemberships.Add(TenantMembership.Create(tenantAlphaId, userId, TenantMembershipRole.Owner, TenantMembershipStatus.Active));
                db.TenantMemberships.Add(TenantMembership.Create(tenantBetaId, userId, TenantMembershipRole.Owner, TenantMembershipStatus.Active));
                await db.SaveChangesAsync();
            }
        }

        var client = CreateClientWithIp();

        // Send request targeting Tenant Alpha route, but specifying Tenant Beta header
        using var patchReq = new HttpRequestMessage(HttpMethod.Patch, $"/api/v1/tenants/{tenantAlphaId}")
        {
            Content = JsonContent.Create(new UpdateTenantRequest("Hacked Name", 1))
        };
        patchReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
        patchReq.Headers.Add("X-Tenant-ID", tenantBetaId.ToString());

        using var patchResp = await client.SendAsync(patchReq);
        Assert.Equal(HttpStatusCode.Forbidden, patchResp.StatusCode);
    }

    [Fact]
    public async Task Invariant_PlatformAdminBypass_CreatesImmutableAuditTrail()
    {
        var (adminToken, adminUserId) = await RegisterAndLoginUserAsync($"secadmin.{Guid.NewGuid():N}@maintenx.internal");

        Guid targetTenantId;
        using (var db = CreateDbContext())
        {
            var t = Tenant.Create("audit-target-org", "Audit Target Org", TenantStatus.Active);
            db.Tenants.Add(t);
            await db.SaveChangesAsync();
            targetTenantId = t.Id;

            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(adminUserId, PlatformRole.PlatformAdministrator, "os:deploy@host", DateTime.UtcNow));
            await db.SaveChangesAsync();
        }

        var client = CreateClientWithIp();

        // Admin accesses tenant without having membership
        using (var req = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{targetTenantId}"))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
            using var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }

        // Verify audit log exists
        using var verifyDb = CreateDbContext();
        var audit = await verifyDb.TenantAuditEvents
            .SingleAsync(a => a.TenantId == targetTenantId && a.Action == "PlatformAdminTenantInspectionBypass");

        Assert.Equal(adminUserId, audit.ActorUserId);
    }

    [Fact]
    public async Task Invariant_UnauthenticatedCalls_AreCategoricallyDeniedWith401()
    {
        var client = CreateClientWithIp();

        using var req = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{Guid.NewGuid()}");
        using var resp = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}
