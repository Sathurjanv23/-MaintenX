namespace MaintenX.IntegrationTests;

using System.Data;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Tenancy.Context;
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
/// FEAT-004 Task 4.4.2 — Platform Administrator Global Bypass Rules Integration Tests.
/// Validates:
/// 1. Platform administrator can establish administrative bypass tenant context without personal membership.
/// 2. Bypasses are explicitly tracked in platform.tenant_audit_events.
/// 3. Platform administrator can update tenant settings via bypass with audit attribution.
/// 4. Ordinary users cannot establish bypass contexts.
/// </summary>
public class PlatformAdminBypassIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public PlatformAdminBypassIntegrationTests()
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

    [Fact]
    public async Task PlatformAdmin_CanEstablishBypassTenantContext_EmitsAuditEvent()
    {
        var (adminToken, adminUserId) = await RegisterAndLoginUserAsync($"bypassadm.{Guid.NewGuid():N}@maintenx.internal");

        Guid targetTenantId;
        using (var db = CreateDbContext())
        {
            var t = Tenant.Create("bypass-corp", "Bypass Corporation", TenantStatus.Active);
            db.Tenants.Add(t);
            await db.SaveChangesAsync();
            targetTenantId = t.Id;

            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(adminUserId, PlatformRole.PlatformAdministrator, "os:deploy@host", DateTime.UtcNow));
            await db.SaveChangesAsync();
        }

        var client = CreateClientWithIp();

        // Admin requests an endpoint requiring tenant context (e.g. GET /api/v1/tenancy/current) with X-Tenant-ID
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenancy/current");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        req.Headers.Add("X-Tenant-ID", targetTenantId.ToString());

        using var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var body = await resp.Content.ReadFromJsonAsync<CurrentTenantContextResponse>();
        Assert.NotNull(body);
        Assert.Equal(targetTenantId, body.TenantId);
        Assert.Equal("bypass-corp", body.TenantSlug);

        // Verify audit event in database
        using var verifyDb = CreateDbContext();
        var audit = await verifyDb.TenantAuditEvents
            .SingleAsync(a => a.TenantId == targetTenantId && a.Action == "PlatformAdminTenantBypassEstablished");

        Assert.Equal(adminUserId, audit.ActorUserId);
        Assert.Contains("bypass-corp", audit.Reason);
    }

    [Fact]
    public async Task PlatformAdmin_Inspection_EmitsInspectionBypassAudit()
    {
        var (adminToken, adminUserId) = await RegisterAndLoginUserAsync($"inspadm.{Guid.NewGuid():N}@maintenx.internal");

        Guid tenantId;
        using (var db = CreateDbContext())
        {
            var t = Tenant.Create("insp-target", "Inspection Target Org", TenantStatus.Active);
            db.Tenants.Add(t);
            await db.SaveChangesAsync();
            tenantId = t.Id;

            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(adminUserId, PlatformRole.PlatformAdministrator, "os:deploy@host", DateTime.UtcNow));
            await db.SaveChangesAsync();
        }

        var client = CreateClientWithIp();

        // Admin inspects tenant by ID
        using var req = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{tenantId}");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        using var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // Verify inspection audit event
        using var verifyDb = CreateDbContext();
        var audit = await verifyDb.TenantAuditEvents
            .SingleAsync(a => a.TenantId == tenantId && a.Action == "PlatformAdminTenantInspectionBypass");

        Assert.Equal(adminUserId, audit.ActorUserId);
    }

    [Fact]
    public async Task PlatformAdmin_UpdateTenantViaBypass_SucceedsAndRecordsBypassAuditReason()
    {
        var (adminToken, adminUserId) = await RegisterAndLoginUserAsync($"updadm.{Guid.NewGuid():N}@maintenx.internal");

        Guid tenantId;
        using (var db = CreateDbContext())
        {
            var t = Tenant.Create("upd-target", "Pre-Update Name", TenantStatus.Active);
            db.Tenants.Add(t);
            await db.SaveChangesAsync();
            tenantId = t.Id;

            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(adminUserId, PlatformRole.PlatformAdministrator, "os:deploy@host", DateTime.UtcNow));
            await db.SaveChangesAsync();
        }

        var client = CreateClientWithIp();

        // Admin updates tenant display name with X-Tenant-ID matching target route
        using var patchReq = new HttpRequestMessage(HttpMethod.Patch, $"/api/v1/tenants/{tenantId}")
        {
            Content = JsonContent.Create(new UpdateTenantRequest("Post-Update Admin Name", 1))
        };
        patchReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        patchReq.Headers.Add("X-Tenant-ID", tenantId.ToString());

        using var patchResp = await client.SendAsync(patchReq);
        Assert.Equal(HttpStatusCode.OK, patchResp.StatusCode);

        // Verify update in DB
        using var verifyDb = CreateDbContext();
        var updatedTenant = await verifyDb.Tenants.SingleAsync(t => t.Id == tenantId);
        Assert.Equal("Post-Update Admin Name", updatedTenant.DisplayName);
        Assert.Equal(2, updatedTenant.Version);

        // Verify audit reason contains PlatformAdminBypass
        var audit = await verifyDb.TenantAuditEvents
            .SingleAsync(a => a.TenantId == tenantId && a.Action == "TenantSettingsUpdated");

        Assert.Equal(adminUserId, audit.ActorUserId);
        Assert.StartsWith("PlatformAdminBypass", audit.Reason);
    }

    [Fact]
    public async Task StandardUser_CannotEstablishBypassTenantContext_Returns404()
    {
        var (userToken, userId) = await RegisterAndLoginUserAsync($"reguser.{Guid.NewGuid():N}@maintenx.internal");

        Guid targetTenantId;
        using (var db = CreateDbContext())
        {
            var t = Tenant.Create("private-corp", "Private Corporation", TenantStatus.Active);
            db.Tenants.Add(t);
            await db.SaveChangesAsync();
            targetTenantId = t.Id;
        }

        var client = CreateClientWithIp();

        // Standard user supplies X-Tenant-ID for an unjoined tenant
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenancy/current");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
        req.Headers.Add("X-Tenant-ID", targetTenantId.ToString());

        using var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);

        // Verify ZERO bypass audit events were emitted
        using var verifyDb = CreateDbContext();
        var audits = await verifyDb.TenantAuditEvents
            .Where(a => a.TenantId == targetTenantId && a.Action.Contains("Bypass"))
            .ToListAsync();

        Assert.Empty(audits);
    }
}
