namespace MaintenX.IntegrationTests;

using System.Data;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Authorization.Policies;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

/// <summary>
/// FEAT-004 Task 4.4.3 — Policy Authorization Handlers & Endpoint Attributes Integration Tests.
/// Validates declarative .RequirePlatformPermission and .RequireTenantPermission endpoint policies:
/// 1. Platform permission policy enforces authoritative server-side grant resolution.
/// 2. Tenant permission policy enforces tenant context and role eligibility fail-closed.
/// 3. Standard users cannot access platform-protected or elevated tenant routes.
/// </summary>
public class PolicyAuthorizationIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public PolicyAuthorizationIntegrationTests()
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
                builder.ConfigureServices(services =>
                {
                    services.AddSingleton<IStartupFilter, TestPolicyEndpointFilter>();
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

    [Fact]
    public async Task RequirePlatformPermission_PlatformAdmin_Returns200OK()
    {
        var (adminToken, adminUserId) = await RegisterAndLoginUserAsync($"platpoladm.{Guid.NewGuid():N}@maintenx.internal");

        using (var db = CreateDbContext())
        {
            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(adminUserId, PlatformRole.PlatformAdministrator, "os:deploy@host", DateTime.UtcNow));
            await db.SaveChangesAsync();
        }

        var client = CreateClientWithIp();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/__test/policy/platform-read");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        using var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task RequirePlatformPermission_StandardUser_Returns403Forbidden()
    {
        var (userToken, _) = await RegisterAndLoginUserAsync($"platpolusr.{Guid.NewGuid():N}@maintenx.internal");

        var client = CreateClientWithIp();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/__test/policy/platform-read");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", userToken);

        using var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task RequireTenantPermission_OwnerRole_Returns200OK()
    {
        var (ownerToken, ownerUserId) = await RegisterAndLoginUserAsync($"polowner.{Guid.NewGuid():N}@maintenx.internal");

        Guid tenantId;
        using (var db = CreateDbContext())
        {
            var tenant = Tenant.Create("pol-owner-org", "Policy Owner Org", TenantStatus.Active);
            db.Tenants.Add(tenant);
            await db.SaveChangesAsync();
            tenantId = tenant.Id;

            using (db.CreatePrivilegedTenantBypassScope("seed-owner"))
            {
                db.TenantMemberships.Add(TenantMembership.Create(tenantId, ownerUserId, TenantMembershipRole.Owner, TenantMembershipStatus.Active));
                await db.SaveChangesAsync();
            }
        }

        var client = CreateClientWithIp();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/__test/policy/tenant-settings");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ownerToken);
        req.Headers.Add("X-Tenant-ID", tenantId.ToString());

        using var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task RequireTenantPermission_MemberRole_WithoutSettingsPermission_Returns403Forbidden()
    {
        var (memberToken, memberUserId) = await RegisterAndLoginUserAsync($"polmember.{Guid.NewGuid():N}@maintenx.internal");

        Guid tenantId;
        using (var db = CreateDbContext())
        {
            var tenant = Tenant.Create("pol-member-org", "Policy Member Org", TenantStatus.Active);
            db.Tenants.Add(tenant);
            await db.SaveChangesAsync();
            tenantId = tenant.Id;

            using (db.CreatePrivilegedTenantBypassScope("seed-member"))
            {
                db.TenantMemberships.Add(TenantMembership.Create(tenantId, memberUserId, TenantMembershipRole.Member, TenantMembershipStatus.Active));
                await db.SaveChangesAsync();
            }
        }

        var client = CreateClientWithIp();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/__test/policy/tenant-settings");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", memberToken);
        req.Headers.Add("X-Tenant-ID", tenantId.ToString());

        using var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task RequireTenantPermission_MissingTenantHeader_Returns400BadRequest()
    {
        var (ownerToken, _) = await RegisterAndLoginUserAsync($"polnoheader.{Guid.NewGuid():N}@maintenx.internal");

        var client = CreateClientWithIp();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/__test/policy/tenant-settings");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ownerToken);
        // Omit X-Tenant-ID header

        using var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    private sealed class TestPolicyEndpointFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                next(app);
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/__test/policy/platform-read", () => Results.Ok(new { status = "platform-allowed" }))
                        .RequirePlatformPermission(PermissionCatalog.Platform.TenantsRead);

                    endpoints.MapGet("/__test/policy/tenant-settings", () => Results.Ok(new { status = "tenant-settings-allowed" }))
                        .RequireTenantPermission(PermissionCatalog.Tenant.SettingsUpdate);
                });
            };
        }
    }
}
