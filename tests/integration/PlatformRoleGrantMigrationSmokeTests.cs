namespace MaintenX.IntegrationTests;

using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

/// <summary>
/// Smoke tests for the AddPlatformRoleGrantPersistence EF Core migration against PostgreSQL 16.
/// Detailed physical constraint, partial index, and concurrency verification belongs to Task 4.2.2.
/// </summary>
public class PlatformRoleGrantMigrationSmokeTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public PlatformRoleGrantMigrationSmokeTests()
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

    private MaintenXDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return new MaintenXDbContext(options);
    }

    [Fact]
    public async Task Migration_CreatesPlatformRoleGrantsTableInPlatformSchema()
    {
        using var context = CreateContext();
        Assert.False(context.Database.HasPendingModelChanges());

        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = 'platform'
              AND table_name = 'platform_role_grants';";

        var count = (long)(await cmd.ExecuteScalarAsync())!;
        Assert.Equal(1L, count);
    }

    [Fact]
    public async Task MigrationRollback_DropsPlatformRoleGrantsOnlyAndReappliesCleanly()
    {
        using var context = CreateContext();
        var migrator = context.GetInfrastructure().GetRequiredService<IMigrator>();

        await migrator.MigrateAsync("20261124000000_AddTenantAuditPersistence");

        using (var conn = new NpgsqlConnection(_isolatedConnectionString))
        {
            await conn.OpenAsync();

            using var cmdGrants = conn.CreateCommand();
            cmdGrants.CommandText = @"
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'platform'
                  AND table_name = 'platform_role_grants';";
            Assert.Equal(0L, (long)(await cmdGrants.ExecuteScalarAsync())!);

            using var cmdExisting = conn.CreateCommand();
            cmdExisting.CommandText = @"
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'platform'
                  AND table_name IN ('tenants', 'users', 'tenant_memberships', 'tenant_audit_events');";
            Assert.Equal(4L, (long)(await cmdExisting.ExecuteScalarAsync())!);
        }

        await context.Database.MigrateAsync();

        using (var conn = new NpgsqlConnection(_isolatedConnectionString))
        {
            await conn.OpenAsync();

            using var cmdRestored = conn.CreateCommand();
            cmdRestored.CommandText = @"
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'platform'
                  AND table_name = 'platform_role_grants';";
            Assert.Equal(1L, (long)(await cmdRestored.ExecuteScalarAsync())!);
        }
    }
}
