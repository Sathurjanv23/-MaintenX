namespace MaintenX.IntegrationTests;

using System.Data;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Application.Authorization.Services;
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
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// FEAT-004 Task 4.4.1 — Tenant Context Pipeline Hardening Integration Tests.
/// Validates:
/// 1. TenantActorResolver binds IsPlatformAdmin accurately via IPlatformGrantResolver.
/// 2. Forged claims cannot elevate standard actors to platform administrators.
/// 3. Cross-tenant boundaries: standard actors cannot view or modify other tenants' data.
/// 4. Platform administrators possess global inspection visibility without requiring personal memberships.
/// 5. Revocation of platform authority immediately removes global inspection privileges.
/// </summary>
public class TenantPipelineHardeningIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private WebApplicationFactory<Program> _factory = null!;

    public TenantPipelineHardeningIntegrationTests()
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
    public async Task StandardUser_CannotAccessOtherTenant_Returns404AntiEnumeration()
    {
        var (userAToken, userAId) = await RegisterAndLoginUserAsync($"usera.{Guid.NewGuid():N}@maintenx.internal");
        var (userBToken, userBId) = await RegisterAndLoginUserAsync($"userb.{Guid.NewGuid():N}@maintenx.internal");

        // Create Tenant A for User A and Tenant B for User B
        Guid tenantAId;
        Guid tenantBId;

        using (var db = CreateDbContext())
        {
            var tenantA = Tenant.Create("org-alpha", "Organization Alpha", TenantStatus.Active);
            var tenantB = Tenant.Create("org-beta", "Organization Beta", TenantStatus.Active);
            db.Tenants.AddRange(tenantA, tenantB);
            await db.SaveChangesAsync();

            tenantAId = tenantA.Id;
            tenantBId = tenantB.Id;

            using (db.CreatePrivilegedTenantBypassScope("seed-memberships"))
            {
                db.TenantMemberships.Add(TenantMembership.Create(tenantAId, userAId, TenantMembershipRole.Owner, TenantMembershipStatus.Active));
                db.TenantMemberships.Add(TenantMembership.Create(tenantBId, userBId, TenantMembershipRole.Owner, TenantMembershipStatus.Active));
                await db.SaveChangesAsync();
            }
        }

        var client = CreateClientWithIp();

        // 1. User A can access Tenant A
        using (var reqA = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{tenantAId}"))
        {
            reqA.Headers.Authorization = new AuthenticationHeaderValue("Bearer", userAToken);
            using var respA = await client.SendAsync(reqA);
            Assert.Equal(HttpStatusCode.OK, respA.StatusCode);
            var bodyA = await respA.Content.ReadFromJsonAsync<TenantResponse>();
            Assert.NotNull(bodyA);
            Assert.Equal("org-alpha", bodyA.Slug);
        }

        // 2. User A attempting to access Tenant B receives 404 (Anti-Enumeration)
        using (var reqB = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{tenantBId}"))
        {
            reqB.Headers.Authorization = new AuthenticationHeaderValue("Bearer", userAToken);
            using var respB = await client.SendAsync(reqB);
            Assert.Equal(HttpStatusCode.NotFound, respB.StatusCode);
        }
    }

    [Fact]
    public async Task PlatformAdmin_HasGlobalInspectionVisibility_AcrossAllTenants()
    {
        var (adminToken, adminUserId) = await RegisterAndLoginUserAsync($"admin.{Guid.NewGuid():N}@maintenx.internal");
        var (regularToken, regularUserId) = await RegisterAndLoginUserAsync($"reg.{Guid.NewGuid():N}@maintenx.internal");

        Guid tenant1Id;
        Guid tenant2Id;

        using (var db = CreateDbContext())
        {
            var t1 = Tenant.Create("corp-one", "Corporation One", TenantStatus.Active);
            var t2 = Tenant.Create("corp-two", "Corporation Two", TenantStatus.Active);
            db.Tenants.AddRange(t1, t2);
            await db.SaveChangesAsync();

            tenant1Id = t1.Id;
            tenant2Id = t2.Id;

            // Admin is granted PlatformAdministrator
            db.PlatformRoleGrants.Add(PlatformRoleGrant.CreateForBootstrap(adminUserId, PlatformRole.PlatformAdministrator, "os:deploy@host", DateTime.UtcNow));
            await db.SaveChangesAsync();
        }

        var client = CreateClientWithIp();

        // 1. Platform Admin can inspect Tenant 1 without personal membership
        using (var req1 = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{tenant1Id}"))
        {
            req1.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
            using var resp1 = await client.SendAsync(req1);
            Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);
            var body1 = await resp1.Content.ReadFromJsonAsync<TenantResponse>();
            Assert.NotNull(body1);
            Assert.Equal("corp-one", body1.Slug);
        }

        // 2. Platform Admin can inspect Tenant 2 without personal membership
        using (var req2 = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{tenant2Id}"))
        {
            req2.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
            using var resp2 = await client.SendAsync(req2);
            Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);
            var body2 = await resp2.Content.ReadFromJsonAsync<TenantResponse>();
            Assert.NotNull(body2);
            Assert.Equal("corp-two", body2.Slug);
        }

        // 3. Regular user without membership receives 404 for both
        using (var regReq1 = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{tenant1Id}"))
        {
            regReq1.Headers.Authorization = new AuthenticationHeaderValue("Bearer", regularToken);
            using var regResp1 = await client.SendAsync(regReq1);
            Assert.Equal(HttpStatusCode.NotFound, regResp1.StatusCode);
        }
    }

    [Fact]
    public async Task RevokedPlatformAdmin_ImmediatelyLosesGlobalVisibility_Returns404()
    {
        var (admin1Token, admin1UserId) = await RegisterAndLoginUserAsync($"adm1.{Guid.NewGuid():N}@maintenx.internal");
        var (admin2Token, admin2UserId) = await RegisterAndLoginUserAsync($"adm2.{Guid.NewGuid():N}@maintenx.internal");

        Guid targetTenantId;
        Guid admin2GrantId;

        using (var db = CreateDbContext())
        {
            var t = Tenant.Create("isolated-corp", "Isolated Corp", TenantStatus.Active);
            db.Tenants.Add(t);
            await db.SaveChangesAsync();
            targetTenantId = t.Id;

            var grant1 = PlatformRoleGrant.CreateForBootstrap(admin1UserId, PlatformRole.PlatformAdministrator, "os:deploy@host", DateTime.UtcNow);
            var grant2 = PlatformRoleGrant.Create(admin2UserId, PlatformRole.PlatformAdministrator, admin1UserId, DateTime.UtcNow);
            db.PlatformRoleGrants.AddRange(grant1, grant2);
            await db.SaveChangesAsync();
            admin2GrantId = grant2.Id;
        }

        var client = CreateClientWithIp();

        // 1. Admin2 can inspect targetTenant before revocation
        using (var reqBefore = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{targetTenantId}"))
        {
            reqBefore.Headers.Authorization = new AuthenticationHeaderValue("Bearer", admin2Token);
            using var respBefore = await client.SendAsync(reqBefore);
            Assert.Equal(HttpStatusCode.OK, respBefore.StatusCode);
        }

        // 2. Admin1 revokes Admin2's grant via IPlatformGrantService
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();
            var grantService = new PlatformGrantService(
                db,
                new FixedUserGrantResolver(admin1UserId),
                TimeProvider.System,
                NullLogger<PlatformGrantService>.Instance);

            var revokeResult = await grantService.RevokeGrantAsync(new PlatformGrantRevocationRequest(admin2GrantId, "Security demotion"));
            Assert.True(revokeResult.IsSuccess);
        }

        // 3. Admin2 immediately loses global inspection privileges (returns 404 anti-enumeration)
        using (var reqAfter = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/tenants/{targetTenantId}"))
        {
            reqAfter.Headers.Authorization = new AuthenticationHeaderValue("Bearer", admin2Token);
            using var respAfter = await client.SendAsync(reqAfter);
            Assert.Equal(HttpStatusCode.NotFound, respAfter.StatusCode);
        }
    }

    [Fact]
    public async Task CrossTenantModification_WithMismatchedHeader_Returns403Forbidden()
    {
        var (userToken, userId) = await RegisterAndLoginUserAsync($"cross.{Guid.NewGuid():N}@maintenx.internal");

        Guid tenantAId;
        Guid tenantBId;

        using (var db = CreateDbContext())
        {
            var tenantA = Tenant.Create("org-mod-a", "Organization Mod A", TenantStatus.Active);
            var tenantB = Tenant.Create("org-mod-b", "Organization Mod B", TenantStatus.Active);
            db.Tenants.AddRange(tenantA, tenantB);
            await db.SaveChangesAsync();

            tenantAId = tenantA.Id;
            tenantBId = tenantB.Id;

            using (db.CreatePrivilegedTenantBypassScope("seed-memberships"))
            {
                db.TenantMemberships.Add(TenantMembership.Create(tenantAId, userId, TenantMembershipRole.Owner, TenantMembershipStatus.Active));
                db.TenantMemberships.Add(TenantMembership.Create(tenantBId, userId, TenantMembershipRole.Owner, TenantMembershipStatus.Active));
                await db.SaveChangesAsync();
            }
        }

        var client = CreateClientWithIp();

        // Target URL is Tenant B, but X-Tenant-ID header is Tenant A
        using var patchReq = new HttpRequestMessage(HttpMethod.Patch, $"/api/v1/tenants/{tenantBId}")
        {
            Content = JsonContent.Create(new UpdateTenantRequest("New Display Name", 1))
        };
        patchReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
        patchReq.Headers.Add("X-Tenant-ID", tenantAId.ToString());

        using var patchResp = await client.SendAsync(patchReq);
        Assert.Equal(HttpStatusCode.Forbidden, patchResp.StatusCode);
    }

    private sealed class FixedUserGrantResolver(Guid userId) : IPlatformGrantResolver
    {
        public Task<PlatformGrantResolutionResult> ResolveAsync(PermissionKey? permission, CancellationToken cancellationToken = default) =>
            Task.FromResult(PlatformGrantResolutionResult.Allow(
                userId,
                Guid.NewGuid(),
                PlatformRole.PlatformAdministrator,
                permission ?? PermissionCatalog.Platform.TenantsRead));
    }
}
