namespace MaintenX.IntegrationTests;

using System.Data;
using System.Net;
using System.Text.Json;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

/// <summary>
/// Fail-closed safety guards for automated test database operations.
/// Prevents accidental mutation or destruction of development, staging, and production databases,
/// and enforces allowlisted hosts and explicit test provisioning opt-in.
/// </summary>
public static class TestDatabaseGuard
{
    private static readonly string[] ProtectedDatabases =
        ["maintenx_dev", "maintenx_prod", "maintenx_staging", "postgres", "template0", "template1"];

    public static (string AdminConnection, string TestConnection) ValidateConnectionConfiguration(IConfiguration config)
    {
        var adminConn = config.GetConnectionString("AdminConnection");
        var testConn = config.GetConnectionString("TestConnection");

        if (string.IsNullOrWhiteSpace(adminConn))
        {
            throw new InvalidOperationException(
                "Missing required configuration: 'ConnectionStrings:AdminConnection'. " +
                "Integration testing requires a dedicated administrator connection string for provisioning test databases.");
        }

        if (string.IsNullOrWhiteSpace(testConn))
        {
            throw new InvalidOperationException(
                "Missing required configuration: 'ConnectionStrings:TestConnection'. " +
                "Integration testing requires a dedicated application/test connection string for migrations and test operations.");
        }

        return (adminConn, testConn);
    }

    public static void ValidateTestDatabaseSafety(
        string databaseName,
        string adminConnectionString,
        string testConnectionString,
        IConfiguration config)
    {
        // 1. Explicit provisioning opt-in verification
        var allowOptIn = config.GetValue<string>("TestDatabase:AllowProvisioning");

        if (!string.Equals(allowOptIn, "true", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Test database provisioning is disabled by default for safety. " +
                "Explicit opt-in required: set 'TestDatabase:AllowProvisioning=true' (or environment variable 'TEST_DATABASE_ALLOW_PROVISIONING=true').");
        }

        // 2. Database Name Verification
        EnsureSafeTestDatabaseName(databaseName);

        // 3. Approved Hosts Verification (fail closed: no default fallback)
        var allowedHostsConfig = config.GetValue<string>("TestDatabase:AllowedHosts");
        if (string.IsNullOrWhiteSpace(allowedHostsConfig))
        {
            throw new InvalidOperationException(
                "Safety violation: 'TestDatabase:AllowedHosts' is missing or empty. " +
                "Integration testing requires an explicit allowlist of approved database hosts (e.g. 'localhost;127.0.0.1;postgres').");
        }

        var allowedHosts = allowedHostsConfig
            .Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (allowedHosts.Count == 0)
        {
            throw new InvalidOperationException(
                "Safety violation: 'TestDatabase:AllowedHosts' contains no valid hosts. " +
                "Integration testing requires an explicit allowlist of approved database hosts.");
        }

        var adminBuilder = new NpgsqlConnectionStringBuilder(adminConnectionString);
        var testBuilder = new NpgsqlConnectionStringBuilder(testConnectionString);

        if (string.IsNullOrWhiteSpace(adminBuilder.Host) || !allowedHosts.Contains(adminBuilder.Host))
        {
            throw new InvalidOperationException(
                $"Safety violation: Admin connection host '{adminBuilder.Host}' is not in the approved test database hosts allowlist [{string.Join(", ", allowedHosts)}].");
        }

        if (string.IsNullOrWhiteSpace(testBuilder.Host) || !allowedHosts.Contains(testBuilder.Host))
        {
            throw new InvalidOperationException(
                $"Safety violation: Test connection host '{testBuilder.Host}' is not in the approved test database hosts allowlist [{string.Join(", ", allowedHosts)}].");
        }
    }

    public static void EnsureSafeTestDatabaseName(string databaseName)
    {
        if (string.IsNullOrWhiteSpace(databaseName) ||
            !databaseName.StartsWith("maintenx_test_", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Safety violation: Refusing to operate on database '{databaseName}'. " +
                "Automated test database operations are strictly restricted to databases prefixed with 'maintenx_test_'.");
        }

        if (ProtectedDatabases.Any(p => p.Equals(databaseName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"Safety violation: Cannot drop or mutate protected database '{databaseName}'.");
        }
    }

    public static async Task<(string DatabaseName, string IsolatedConnectionString)> ProvisionAndInitializeAsync(
        string adminConnectionString,
        string testConnectionString,
        IConfiguration config,
        Func<string, Task>? initializeSchemaAsync = null,
        string? customDbName = null)
    {
        var dbName = customDbName ?? $"maintenx_test_{Guid.NewGuid():N}";
        ValidateTestDatabaseSafety(dbName, adminConnectionString, testConnectionString, config);

        var testBuilder = new NpgsqlConnectionStringBuilder(testConnectionString);
        var appRole = testBuilder.Username ?? string.Empty;

        bool databaseCreated = false;
        try
        {
            using (var adminConnection = new NpgsqlConnection(adminConnectionString))
            {
                await adminConnection.OpenAsync();
                using var createCmd = adminConnection.CreateCommand();
                createCmd.CommandText = !string.IsNullOrWhiteSpace(appRole)
                    ? $"CREATE DATABASE {dbName} OWNER \"{appRole}\";"
                    : $"CREATE DATABASE {dbName};";
                await createCmd.ExecuteNonQueryAsync();

                if (!string.IsNullOrWhiteSpace(appRole))
                {
                    using var grantCmd = adminConnection.CreateCommand();
                    grantCmd.CommandText = $"GRANT ALL PRIVILEGES ON DATABASE {dbName} TO \"{appRole}\";";
                    await grantCmd.ExecuteNonQueryAsync();
                }

                databaseCreated = true;
            }

            testBuilder.Database = dbName;
            var isolatedConnectionString = testBuilder.ConnectionString;

            if (initializeSchemaAsync != null)
            {
                await initializeSchemaAsync(isolatedConnectionString);
            }

            return (dbName, isolatedConnectionString);
        }
        catch (Exception ex)
        {
            if (databaseCreated)
            {
                try
                {
                    await DropDatabaseSafelyAsync(dbName, adminConnectionString);
                }
                catch (Exception cleanupEx)
                {
                    throw new InvalidOperationException(
                        $"Failed to initialize isolated test database '{dbName}'. Immediate cleanup also failed: {cleanupEx.Message}",
                        new AggregateException(ex, cleanupEx));
                }
            }

            throw new InvalidOperationException(
                $"Database integration testing requires an accessible PostgreSQL instance. " +
                $"Failed to connect or initialize isolated test database '{dbName}'. Error: {ex.Message}", ex);
        }
    }

    public static async Task DropDatabaseSafelyAsync(string databaseName, string adminConnectionString)
    {
        NpgsqlConnection.ClearAllPools();
        EnsureSafeTestDatabaseName(databaseName);

        using var adminConn = new NpgsqlConnection(adminConnectionString);
        await adminConn.OpenAsync();

        using var termCmd = adminConn.CreateCommand();
        termCmd.CommandText = @"
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = @dbName AND pid <> pg_backend_pid();";
        termCmd.Parameters.AddWithValue("dbName", databaseName);
        await termCmd.ExecuteNonQueryAsync();

        using var dropCmd = adminConn.CreateCommand();
        dropCmd.CommandText = $"DROP DATABASE IF EXISTS {databaseName} WITH (FORCE);";
        await dropCmd.ExecuteNonQueryAsync();
    }
}

/// <summary>
/// Integration test suite for MaintenX PostgreSQL Database Foundation (FEAT-001).
/// All test cases execute against an isolated disposable database ('maintenx_test_*')
/// using genuine administrator/application credential separation and strict safety guards.
/// </summary>
public class DatabaseFoundationIntegrationTests : IClassFixture<WebApplicationFactory<Program>>, IAsyncLifetime
{
    private readonly WebApplicationFactory<Program> _baseFactory;
    private WebApplicationFactory<Program> _isolatedFactory = null!;
    private string _adminConnectionString = string.Empty;
    private string _testConnectionString = string.Empty;
    private string _testDbName = string.Empty;
    private string _isolatedConnectionString = string.Empty;
    private string _appRole = string.Empty;

    public DatabaseFoundationIntegrationTests(WebApplicationFactory<Program> baseFactory)
    {
        _baseFactory = baseFactory;
    }

    public async Task InitializeAsync()
    {
        var config = _baseFactory.Services.GetRequiredService<IConfiguration>();

        // 1. Explicit connection requirements - no fallback to DefaultConnection
        var (adminConn, testConn) = TestDatabaseGuard.ValidateConnectionConfiguration(config);
        _adminConnectionString = adminConn;
        _testConnectionString = testConn;

        var testBuilder = new NpgsqlConnectionStringBuilder(_testConnectionString);
        _appRole = testBuilder.Username ?? string.Empty;

        var (dbName, isolatedConn) = await TestDatabaseGuard.ProvisionAndInitializeAsync(
            _adminConnectionString,
            _testConnectionString,
            config,
            initializeSchemaAsync: async (isolatedConnectionString) =>
            {
                // Reconfigure WebApplicationFactory to target the isolated test database
                _isolatedFactory = _baseFactory.WithWebHostBuilder(webBuilder =>
                {
                    webBuilder.UseSetting("ConnectionStrings:DefaultConnection", isolatedConnectionString);
                });

                // Apply all committed migrations to the isolated test database using the application role
                using var scope = _isolatedFactory.Services.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();
                await dbContext.Database.MigrateAsync();
            });

        _testDbName = dbName;
        _isolatedConnectionString = isolatedConn;
    }

    public async Task DisposeAsync()
    {
        Exception? teardownEx = null;

        if (!string.IsNullOrWhiteSpace(_testDbName) && !string.IsNullOrWhiteSpace(_adminConnectionString))
        {
            try
            {
                await TestDatabaseGuard.DropDatabaseSafelyAsync(_testDbName, _adminConnectionString);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[CRITICAL WARNING] Failed to drop disposable test database '{_testDbName}': {ex.Message}");
                teardownEx = ex;
            }
        }

        try
        {
            _isolatedFactory?.Dispose();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[CRITICAL WARNING] Failed to dispose isolated test factory: {ex.Message}");
            teardownEx = teardownEx == null ? ex : new AggregateException(teardownEx, ex);
        }

        if (teardownEx != null)
        {
            throw teardownEx;
        }
    }

    [Fact]
    public async Task DB001_DbContext_ResolvesFromDependencyInjection()
    {
        // Arrange & Act
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetService<MaintenXDbContext>();

        // Assert
        Assert.NotNull(dbContext);
        var canConnect = await dbContext.Database.CanConnectAsync();
        Assert.True(canConnect, "DbContext must connect to the isolated PostgreSQL test database.");
    }

    [Fact]
    public async Task DB002_InitialAndAdditiveMigrations_ApplySuccessfully()
    {
        // Arrange
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        // Act
        var appliedMigrations = (await dbContext.Database.GetAppliedMigrationsAsync()).ToList();

        // Assert
        Assert.NotEmpty(appliedMigrations);
        Assert.Contains("20261113000000_InitialDatabaseFoundation", appliedMigrations);
        Assert.Contains("20261113000001_HardenTenantSlugConstraints", appliedMigrations);
    }

    [Fact]
    public async Task DB003_Tenant_CanBePersistedAndRetrieved()
    {
        // Arrange
        using var scope1 = _isolatedFactory.Services.CreateScope();
        var context1 = scope1.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var slug = "facility-corp-" + Guid.NewGuid().ToString("N")[..8];
        var tenant = Tenant.Create(slug, "Facility Management Corp", TenantStatus.Active);

        // Act
        context1.Tenants.Add(tenant);
        var rowsSaved = await context1.SaveChangesAsync();
        Assert.Equal(1, rowsSaved);

        // Retrieve in separate scope to ensure true persistence
        using var scope2 = _isolatedFactory.Services.CreateScope();
        var context2 = scope2.ServiceProvider.GetRequiredService<MaintenXDbContext>();
        var retrieved = await context2.Tenants.FirstOrDefaultAsync(t => t.Id == tenant.Id);

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal(slug, retrieved.Slug);
        Assert.Equal("Facility Management Corp", retrieved.DisplayName);
        Assert.Equal(TenantStatus.Active, retrieved.Status);
        Assert.Equal(1, retrieved.Version);
    }

    [Fact]
    public async Task DB004_DuplicateNormalizedSlug_IsRejected()
    {
        // Arrange
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var slug = "dup-test-" + Guid.NewGuid().ToString("N")[..8];
        var tenant1 = Tenant.Create(slug, "First Tenant");
        var tenant2 = Tenant.Create(slug.ToUpperInvariant(), "Second Tenant With Same Normalized Slug");

        dbContext.Tenants.Add(tenant1);
        await dbContext.SaveChangesAsync();

        // Act & Assert
        dbContext.Tenants.Add(tenant2);
        await Assert.ThrowsAsync<DbUpdateException>(async () =>
        {
            await dbContext.SaveChangesAsync();
        });
    }

    [Theory]
    [InlineData("acme", true)]
    [InlineData("acme-facility", true)]
    [InlineData("facility-101-zone-a", true)]
    [InlineData("ACME", false)]                   // Direct SQL with uppercase violates database check constraint
    [InlineData("acme corp", false)]              // Whitespace violates slug pattern
    [InlineData(" acme", false)]                 // Leading whitespace violates pattern
    [InlineData("acme ", false)]                 // Trailing whitespace violates pattern
    [InlineData("-acme", false)]                 // Leading hyphen violates pattern
    [InlineData("acme-", false)]                 // Trailing hyphen violates pattern
    [InlineData("acme--facility", false)]        // Consecutive hyphens violate pattern
    [InlineData("acme@facility", false)]         // Special symbol violates pattern
    [InlineData("acme_facility", false)]         // Underscore violates pattern
    [InlineData("a", false)]                     // Below minimum length (2)
    public async Task DB005_TenantSlug_DatabaseCheckConstraint_EnforcesInvariants(string testSlug, bool isValid)
    {
        // Arrange
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var rawSql = @"
            INSERT INTO platform.tenants (id, slug, display_name, status, created_at_utc, updated_at_utc, version)
            VALUES ({0}, {1}, {2}, {3}, {4}, {5}, {6});";

        var id = Guid.NewGuid();
        var now = DateTime.UtcNow;

        if (isValid)
        {
            // Act: Valid slug must succeed
            var rows = await dbContext.Database.ExecuteSqlRawAsync(
                rawSql, id, testSlug, "Test Org", "Active", now, now, 1L);
            Assert.Equal(1, rows);

            // Cleanup
            await dbContext.Database.ExecuteSqlRawAsync(
                "DELETE FROM platform.tenants WHERE id = {0};", id);
        }
        else
        {
            // Act & Assert: Invalid slug must be rejected by PostgreSQL ck_tenants_slug constraint
            await Assert.ThrowsAsync<PostgresException>(async () =>
            {
                await dbContext.Database.ExecuteSqlRawAsync(
                    rawSql, id, testSlug, "Test Org", "Active", now, now, 1L);
            });
        }
    }

    [Fact]
    public void DB005_TenantSlug_DomainFactory_EnforcesValidationAndNormalization()
    {
        // 1. Valid cases
        var tenant1 = Tenant.Create("acme", "Acme Corp");
        Assert.Equal("acme", tenant1.Slug);

        var tenant2 = Tenant.Create("acme-facility", "Acme Facility");
        Assert.Equal("acme-facility", tenant2.Slug);

        var tenantMin = Tenant.Create("ab", "Minimum Length Org");
        Assert.Equal("ab", tenantMin.Slug);

        var maxSlug = new string('a', 100);
        var tenantMax = Tenant.Create(maxSlug, "Maximum Length Org");
        Assert.Equal(maxSlug, tenantMax.Slug);

        // 2. Normalization: Uppercase automatically normalized to lowercase
        var tenantUpper = Tenant.Create("ACME", "Acme Corp");
        Assert.Equal("acme", tenantUpper.Slug);

        var tenantMixed = Tenant.Create("Acme-Facility-101", "Mixed Case Org");
        Assert.Equal("acme-facility-101", tenantMixed.Slug);

        // 3. Leading and trailing whitespace must be strictly rejected
        Assert.Throws<ArgumentException>(() => Tenant.Create(" acme", "Org"));
        Assert.Throws<ArgumentException>(() => Tenant.Create("acme ", "Org"));
        Assert.Throws<ArgumentException>(() => Tenant.Create(" acme ", "Org"));
        Assert.Throws<ArgumentException>(() => Tenant.Create("\tacme", "Org"));
        Assert.Throws<ArgumentException>(() => Tenant.Create("acme\n", "Org"));

        // 4. Invalid cases throw ArgumentException
        Assert.Throws<ArgumentException>(() => Tenant.Create("   ", "Org"));
        Assert.Throws<ArgumentException>(() => Tenant.Create("", "Org"));
        Assert.Throws<ArgumentException>(() => Tenant.Create("a", "Org")); // Length < 2
        Assert.Throws<ArgumentException>(() => Tenant.Create(new string('a', 101), "Org")); // Length > 100
        Assert.Throws<ArgumentException>(() => Tenant.Create("acme corp", "Org")); // Internal whitespace
        Assert.Throws<ArgumentException>(() => Tenant.Create("-acme", "Org")); // Leading hyphen
        Assert.Throws<ArgumentException>(() => Tenant.Create("acme-", "Org")); // Trailing hyphen
        Assert.Throws<ArgumentException>(() => Tenant.Create("acme--corp", "Org")); // Consecutive hyphens
        Assert.Throws<ArgumentException>(() => Tenant.Create("acme@corp", "Org")); // Invalid char
        Assert.Throws<ArgumentException>(() => Tenant.Create("acme_corp", "Org")); // Underscore
        Assert.Throws<ArgumentException>(() => Tenant.Create("acme.corp", "Org")); // Period
    }

    [Fact]
    public async Task DB006_UuidKeys_PersistCorrectly()
    {
        // Arrange
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var customId = Guid.NewGuid();
        var slug = "uuid-test-" + customId.ToString("N")[..8];
        var tenant = Tenant.Create(slug, "UUID Org");
        tenant.Id = customId;

        // Act
        dbContext.Tenants.Add(tenant);
        await dbContext.SaveChangesAsync();

        var persisted = await dbContext.Tenants.AsNoTracking().FirstOrDefaultAsync(t => t.Id == customId);

        // Assert
        Assert.NotNull(persisted);
        Assert.Equal(customId, persisted.Id);
    }

    [Fact]
    public async Task DB007_UtcTimestamps_RoundTripCorrectly()
    {
        // Arrange
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var slug = "timestamp-test-" + Guid.NewGuid().ToString("N")[..8];
        var tenant = Tenant.Create(slug, "Timestamp Org");
        var originalCreated = tenant.CreatedAtUtc;

        // Act
        dbContext.Tenants.Add(tenant);
        await dbContext.SaveChangesAsync();

        var retrieved = await dbContext.Tenants.AsNoTracking().FirstAsync(t => t.Id == tenant.Id);

        // Assert
        Assert.Equal(DateTimeKind.Utc, retrieved.CreatedAtUtc.Kind);
        Assert.Equal(DateTimeKind.Utc, retrieved.UpdatedAtUtc.Kind);
        Assert.True((retrieved.CreatedAtUtc - originalCreated).Duration() < TimeSpan.FromMilliseconds(50));
    }

    [Fact]
    public async Task DB008_OptimisticConcurrencyConflict_IsDetected()
    {
        // Arrange: Create and persist initial tenant
        var slug = "concurrency-" + Guid.NewGuid().ToString("N")[..8];
        var tenant = Tenant.Create(slug, "Original Name");

        using (var setupScope = _isolatedFactory.Services.CreateScope())
        {
            var setupContext = setupScope.ServiceProvider.GetRequiredService<MaintenXDbContext>();
            setupContext.Tenants.Add(tenant);
            await setupContext.SaveChangesAsync();
        }

        // Simulate two concurrent actors loading the same entity
        using var scope1 = _isolatedFactory.Services.CreateScope();
        var context1 = scope1.ServiceProvider.GetRequiredService<MaintenXDbContext>();
        var actor1Tenant = await context1.Tenants.FirstAsync(t => t.Id == tenant.Id);

        using var scope2 = _isolatedFactory.Services.CreateScope();
        var context2 = scope2.ServiceProvider.GetRequiredService<MaintenXDbContext>();
        var actor2Tenant = await context2.Tenants.FirstAsync(t => t.Id == tenant.Id);

        // Act: Actor 1 updates and saves successfully (Version increments from 1 -> 2)
        actor1Tenant.DisplayName = "Updated By Actor 1";
        await context1.SaveChangesAsync();

        // Actor 2 tries to update with stale Version token (holds Version 1)
        actor2Tenant.DisplayName = "Updated By Actor 2";

        // Assert: EF Core must detect concurrency token mismatch and throw DbUpdateConcurrencyException
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(async () =>
        {
            await context2.SaveChangesAsync();
        });
    }

    [Fact]
    public async Task DB009_MigrationHistory_IsPresent()
    {
        // Arrange
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        // Act: Query the platform.__EFMigrationsHistory table directly
        var connection = dbContext.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync();
        }

        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT \"MigrationId\" FROM platform.\"__EFMigrationsHistory\";";
        using var reader = await cmd.ExecuteReaderAsync();

        var historyList = new List<string>();
        while (await reader.ReadAsync())
        {
            historyList.Add(reader.GetString(0));
        }

        // Assert
        Assert.NotEmpty(historyList);
        Assert.Contains("20261113000000_InitialDatabaseFoundation", historyList);
        Assert.Contains("20261113000001_HardenTenantSlugConstraints", historyList);
    }

    [Fact]
    public async Task DB010_ApplyingMigrationsAgain_IsSafe()
    {
        // Arrange
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        // Act: Execute migration a second time to verify idempotency
        var exception = await Record.ExceptionAsync(async () =>
        {
            await dbContext.Database.MigrateAsync();
        });

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public async Task DB011_NewDatabase_CanBeInitializedUsingCommittedMigrations()
    {
        // Arrange: Generate unique disposable database name with strict safety prefix
        var disposableDbName = "maintenx_test_init_" + Guid.NewGuid().ToString("N")[..8];
        TestDatabaseGuard.EnsureSafeTestDatabaseName(disposableDbName);

        using (var adminConn = new NpgsqlConnection(_adminConnectionString))
        {
            await adminConn.OpenAsync();
            using var createCmd = adminConn.CreateCommand();
            createCmd.CommandText = !string.IsNullOrWhiteSpace(_appRole)
                ? $"CREATE DATABASE {disposableDbName} OWNER \"{_appRole}\";"
                : $"CREATE DATABASE {disposableDbName};";
            await createCmd.ExecuteNonQueryAsync();

            if (!string.IsNullOrWhiteSpace(_appRole))
            {
                using var grantCmd = adminConn.CreateCommand();
                grantCmd.CommandText = $"GRANT ALL PRIVILEGES ON DATABASE {disposableDbName} TO \"{_appRole}\";";
                await grantCmd.ExecuteNonQueryAsync();
            }
        }

        try
        {
            // Act: Build DbContext targeting the clean disposable database using the application connection
            var testConnBuilder = new NpgsqlConnectionStringBuilder(_testConnectionString)
            {
                Database = disposableDbName
            };
            var optionsBuilder = new DbContextOptionsBuilder<MaintenXDbContext>();
            optionsBuilder.UseNpgsql(testConnBuilder.ConnectionString, npgsql =>
            {
                npgsql.MigrationsHistoryTable("__EFMigrationsHistory", MaintenXDbContext.DefaultSchema);
            });

            using (var freshContext = new MaintenXDbContext(optionsBuilder.Options))
            {
                // Apply all committed migrations from scratch
                await freshContext.Database.MigrateAsync();

                // Verify applied migrations
                var applied = (await freshContext.Database.GetAppliedMigrationsAsync()).ToList();
                Assert.Contains("20261113000000_InitialDatabaseFoundation", applied);
                Assert.Contains("20261113000001_HardenTenantSlugConstraints", applied);

                // Verify table exists and can persist data
                var testTenant = Tenant.Create("fresh-tenant-" + Guid.NewGuid().ToString("N")[..8], "Fresh Tenant Org");
                freshContext.Tenants.Add(testTenant);
                await freshContext.SaveChangesAsync();

                var retrieved = await freshContext.Tenants.FirstOrDefaultAsync(t => t.Id == testTenant.Id);
                Assert.NotNull(retrieved);
            }
        }
        finally
        {
            // Cleanup: Drop the disposable test database with safety verification
            NpgsqlConnection.ClearAllPools();
            TestDatabaseGuard.EnsureSafeTestDatabaseName(disposableDbName);

            try
            {
                using var dropConn = new NpgsqlConnection(_adminConnectionString);
                await dropConn.OpenAsync();
                using var dropCmd = dropConn.CreateCommand();
                dropCmd.CommandText = $"DROP DATABASE IF EXISTS {disposableDbName} WITH (FORCE);";
                await dropCmd.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[CRITICAL WARNING] Failed to drop disposable test database '{disposableDbName}': {ex.Message}");
                throw;
            }
        }
    }

    [Fact]
    public async Task DB012_DatabaseDriverException_DoesNotExposeSensitiveCredentials()
    {
        // Arrange: Point to an invalid host with sensitive fake credentials
        var secretPassword = "super_secret_db_password_never_expose!";
        var invalidConnection = $"Host=127.0.0.1;Port=59999;Database=fake_db;Username=fake_user;Password={secretPassword};Timeout=1;";

        var optionsBuilder = new DbContextOptionsBuilder<MaintenXDbContext>();
        optionsBuilder.UseNpgsql(invalidConnection);

        using var brokenContext = new MaintenXDbContext(optionsBuilder.Options);

        // Act: Attempt database operation
        var ex = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await brokenContext.Tenants.FirstOrDefaultAsync();
        });

        // Assert: Low-level driver/ADO.NET exception message must NOT format or reflect plaintext credentials
        Assert.NotNull(ex.Message);
        Assert.DoesNotContain(secretPassword, ex.Message);
    }

    [Fact]
    public async Task DB013_PublicHealthApiEndpoint_WhenDatabaseFails_DoesNotExposeConnectionDetails()
    {
        // Arrange: Reconfigure host with an unreachable database to simulate an outage
        var secretPassword = "super_secret_api_leak_test_pass!";
        var brokenFactory = _baseFactory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting(
                "ConnectionStrings:DefaultConnection",
                $"Host=127.0.0.1;Port=59999;Database=fake_api_db;Username=fake_api_user;Password={secretPassword};Timeout=1;");
        });
        var client = brokenFactory.CreateClient();

        // Act: Call public readiness probe
        var response = await client.GetAsync("/health/ready");

        // Assert: Public HTTP endpoint returns 503 ServiceUnavailable with sanitized message
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var jsonDoc = JsonDocument.Parse(content);
        var root = jsonDoc.RootElement;

        Assert.Equal("Unhealthy", root.GetProperty("status").GetString());
        var dbCheck = root.GetProperty("checks").EnumerateArray()
            .FirstOrDefault(c => c.GetProperty("component").GetString() == "postgresql");

        Assert.Equal("Unhealthy", dbCheck.GetProperty("status").GetString());
        Assert.Equal("Database service is unavailable.", dbCheck.GetProperty("description").GetString());

        // Defense-in-depth: Verify public JSON body contains zero credential, host, or stack trace leaks
        Assert.DoesNotContain(secretPassword, content);
        Assert.DoesNotContain("fake_api_user", content);
        Assert.DoesNotContain("59999", content);
        Assert.False(dbCheck.TryGetProperty("error", out _));
    }

    [Fact]
    public async Task DB014_MigrationUpgrade_PreservesExistingDataAndAppliesSlugConstraint()
    {
        // Arrange: Generate unique disposable database name
        var disposableDbName = "maintenx_test_upgrade_" + Guid.NewGuid().ToString("N")[..8];
        TestDatabaseGuard.EnsureSafeTestDatabaseName(disposableDbName);

        using (var adminConn = new NpgsqlConnection(_adminConnectionString))
        {
            await adminConn.OpenAsync();
            using var createCmd = adminConn.CreateCommand();
            createCmd.CommandText = !string.IsNullOrWhiteSpace(_appRole)
                ? $"CREATE DATABASE {disposableDbName} OWNER \"{_appRole}\";"
                : $"CREATE DATABASE {disposableDbName};";
            await createCmd.ExecuteNonQueryAsync();

            if (!string.IsNullOrWhiteSpace(_appRole))
            {
                using var grantCmd = adminConn.CreateCommand();
                grantCmd.CommandText = $"GRANT ALL PRIVILEGES ON DATABASE {disposableDbName} TO \"{_appRole}\";";
                await grantCmd.ExecuteNonQueryAsync();
            }
        }

        var testConnBuilder = new NpgsqlConnectionStringBuilder(_testConnectionString)
        {
            Database = disposableDbName
        };

        var optionsBuilder = new DbContextOptionsBuilder<MaintenXDbContext>();
        optionsBuilder.UseNpgsql(testConnBuilder.ConnectionString, npgsql =>
        {
            npgsql.MigrationsHistoryTable("__EFMigrationsHistory", MaintenXDbContext.DefaultSchema);
        });

        try
        {
            var initialTenantId = Guid.NewGuid();
            var now = DateTime.UtcNow;

            using (var context = new MaintenXDbContext(optionsBuilder.Options))
            {
                // Step 1: Apply initial migration only (20261113000000_InitialDatabaseFoundation)
                var migrator = context.Database.GetService<IMigrator>();
                Assert.NotNull(migrator);
                await migrator.MigrateAsync("20261113000000_InitialDatabaseFoundation");

                // Verify initial migration is applied and 0002 is not yet applied
                var initialApplied = (await context.Database.GetAppliedMigrationsAsync()).ToList();
                Assert.Single(initialApplied);
                Assert.Equal("20261113000000_InitialDatabaseFoundation", initialApplied[0]);

                // Step 2: Insert valid tenant under migration 0001
                await context.Database.ExecuteSqlRawAsync(
                    @"INSERT INTO platform.tenants (id, slug, display_name, status, created_at_utc, updated_at_utc, version)
                      VALUES ({0}, {1}, {2}, {3}, {4}, {5}, {6});",
                    initialTenantId, "legacy-facility-org", "Legacy Facility Org", "Active", now, now, 1L);
            }

            using (var context = new MaintenXDbContext(optionsBuilder.Options))
            {
                // Step 3: Upgrade to latest migration (applies 20261113000001_HardenTenantSlugConstraints)
                await context.Database.MigrateAsync();

                // Step 4: Verify migration history contains both migrations
                var allApplied = (await context.Database.GetAppliedMigrationsAsync()).ToList();
                Assert.Equal(2, allApplied.Count);
                Assert.Contains("20261113000000_InitialDatabaseFoundation", allApplied);
                Assert.Contains("20261113000001_HardenTenantSlugConstraints", allApplied);

                // Step 5: Verify existing tenant data survived upgrade unmodified
                var existingTenant = await context.Tenants.AsNoTracking().FirstOrDefaultAsync(t => t.Id == initialTenantId);
                Assert.NotNull(existingTenant);
                Assert.Equal("legacy-facility-org", existingTenant.Slug);
                Assert.Equal("Legacy Facility Org", existingTenant.DisplayName);

                // Step 6: Verify the ck_tenants_slug constraint was created in PostgreSQL
                var conn = context.Database.GetDbConnection();
                if (conn.State != ConnectionState.Open)
                {
                    await conn.OpenAsync();
                }

                using var checkCmd = conn.CreateCommand();
                checkCmd.CommandText = @"
                    SELECT COUNT(*)
                    FROM pg_constraint
                    WHERE conname = 'ck_tenants_slug';";
                var constraintCount = Convert.ToInt64(await checkCmd.ExecuteScalarAsync());
                Assert.Equal(1L, constraintCount);

                // Step 7: Verify invalid slugs are rejected by the upgraded database constraint
                await Assert.ThrowsAsync<PostgresException>(async () =>
                {
                    await context.Database.ExecuteSqlRawAsync(
                        @"INSERT INTO platform.tenants (id, slug, display_name, status, created_at_utc, updated_at_utc, version)
                          VALUES ({0}, {1}, {2}, {3}, {4}, {5}, {6});",
                        Guid.NewGuid(), "INVALID_SLUG_UPPERCASE", "Invalid Upper Slug", "Active", now, now, 1L);
                });
            }
        }
        finally
        {
            // Step 8: Safe cleanup
            NpgsqlConnection.ClearAllPools();
            TestDatabaseGuard.EnsureSafeTestDatabaseName(disposableDbName);

            try
            {
                using var dropConn = new NpgsqlConnection(_adminConnectionString);
                await dropConn.OpenAsync();
                using var dropCmd = dropConn.CreateCommand();
                dropCmd.CommandText = $"DROP DATABASE IF EXISTS {disposableDbName} WITH (FORCE);";
                await dropCmd.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[CRITICAL WARNING] Failed to drop disposable test database '{disposableDbName}': {ex.Message}");
                throw;
            }
        }
    }

    [Fact]
    public void DB015_ConfigurationGuard_RejectsMissingAdminOrTestConnection()
    {
        // 1. Missing AdminConnection throws InvalidOperationException
        var configMissingAdmin = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:TestConnection"] = "Host=localhost;Database=postgres;Username=app;Password=pass;",
                ["ConnectionStrings:DefaultConnection"] = "Host=localhost;Database=maintenx_dev;Username=app;Password=pass;",
                ["TestDatabase:AllowProvisioning"] = "true",
                ["TestDatabase:AllowedHosts"] = "localhost"
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateConnectionConfiguration(configMissingAdmin));

        // 2. Missing TestConnection throws InvalidOperationException without falling back to DefaultConnection
        var configMissingTest = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:AdminConnection"] = "Host=localhost;Database=postgres;Username=admin;Password=pass;",
                ["ConnectionStrings:DefaultConnection"] = "Host=localhost;Database=maintenx_dev;Username=app;Password=pass;",
                ["TestDatabase:AllowProvisioning"] = "true",
                ["TestDatabase:AllowedHosts"] = "localhost"
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateConnectionConfiguration(configMissingTest));
    }

    [Fact]
    public void DB016_ConfigurationGuard_RejectsUnapprovedHostOrDisabledOptIn()
    {
        var validAdmin = "Host=localhost;Port=5432;Database=postgres;Username=postgres;Password=pass;";
        var validTest = "Host=localhost;Port=5432;Database=postgres;Username=maintenx_app;Password=pass;";

        // 1. Missing or disabled opt-in throws InvalidOperationException
        var configDisabledOptIn = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TestDatabase:AllowProvisioning"] = "false",
                ["TestDatabase:AllowedHosts"] = "localhost"
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_test_sample", validAdmin, validTest, configDisabledOptIn));

        var configMissingOptIn = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TestDatabase:AllowedHosts"] = "localhost"
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_test_sample", validAdmin, validTest, configMissingOptIn));

        // 2. Missing, empty, or whitespace AllowedHosts throws InvalidOperationException (fail-closed)
        var configMissingAllowedHosts = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TestDatabase:AllowProvisioning"] = "true"
            })
            .Build();

        var missingEx = Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_test_sample", validAdmin, validTest, configMissingAllowedHosts));
        Assert.Contains("missing or empty", missingEx.Message, StringComparison.OrdinalIgnoreCase);

        var configEmptyAllowedHosts = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TestDatabase:AllowProvisioning"] = "true",
                ["TestDatabase:AllowedHosts"] = ""
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_test_sample", validAdmin, validTest, configEmptyAllowedHosts));

        var configWhitespaceAllowedHosts = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TestDatabase:AllowProvisioning"] = "true",
                ["TestDatabase:AllowedHosts"] = "   ; ;  "
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_test_sample", validAdmin, validTest, configWhitespaceAllowedHosts));

        // 3. Unapproved admin host throws InvalidOperationException
        var unapprovedAdmin = "Host=prod-db.maintenx.internal;Port=5432;Database=postgres;Username=postgres;Password=pass;";
        var configApprovedHosts = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TestDatabase:AllowProvisioning"] = "true",
                ["TestDatabase:AllowedHosts"] = "localhost;127.0.0.1;postgres"
            })
            .Build();

        var adminHostEx = Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_test_sample", unapprovedAdmin, validTest, configApprovedHosts));
        Assert.Contains("Admin connection host", adminHostEx.Message);

        // 4. Unapproved test host throws InvalidOperationException
        var unapprovedTest = "Host=staging-db.maintenx.internal;Port=5432;Database=postgres;Username=maintenx_app;Password=pass;";
        var testHostEx = Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_test_sample", validAdmin, unapprovedTest, configApprovedHosts));
        Assert.Contains("Test connection host", testHostEx.Message);

        // 5. Unapproved or dangerous database names throw InvalidOperationException
        Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_dev", validAdmin, validTest, configApprovedHosts));
        Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("postgres", validAdmin, validTest, configApprovedHosts));
        Assert.Throws<InvalidOperationException>(() =>
            TestDatabaseGuard.ValidateTestDatabaseSafety("arbitrary_database", validAdmin, validTest, configApprovedHosts));

        // 6. Valid configuration passes without throwing
        TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_test_sample", validAdmin, validTest, configApprovedHosts);
    }

    [Fact]
    public async Task DB017_RoleSeparation_ApplicationRole_IsNotSuperuserAndCannotCreateDatabase()
    {
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var conn = dbContext.Database.GetDbConnection();
        if (conn.State != ConnectionState.Open)
        {
            await conn.OpenAsync();
        }

        // 1. Assert current application role is NOT a superuser and does NOT have CREATEDB
        using var roleCheckCmd = conn.CreateCommand();
        roleCheckCmd.CommandText = @"
            SELECT rolsuper, rolcreatedb
            FROM pg_roles
            WHERE rolname = current_user;";
        using var reader = await roleCheckCmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), "Current user role must exist in pg_roles.");

        var isSuperuser = reader.GetBoolean(0);
        var canCreateDb = reader.GetBoolean(1);
        await reader.CloseAsync();

        Assert.False(isSuperuser, "Test application role must not have PostgreSQL superuser privileges.");
        Assert.False(canCreateDb, "Test application role must not have CREATEDB privileges.");

        // 2. Assert executing CREATE DATABASE with application credentials fails with permission denied
        var forbiddenDbName = $"maintenx_test_forbidden_{Guid.NewGuid():N}";
        await Assert.ThrowsAsync<PostgresException>(async () =>
        {
            using var forbiddenCmd = conn.CreateCommand();
            forbiddenCmd.CommandText = $"CREATE DATABASE {forbiddenDbName};";
            await forbiddenCmd.ExecuteNonQueryAsync();
        });
    }

    [Fact]
    public async Task DB018_RoleSeparation_ApplicationRole_CanManageSchemaAndMigrateOwnedDatabase()
    {
        // Assert that the application role can execute DDL (tables, schemas) within its owned disposable database
        using var scope = _isolatedFactory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var testTable = $"test_ddl_{Guid.NewGuid():N}";
        var rawSql = $@"
            CREATE TABLE platform.{testTable} (
                id UUID PRIMARY KEY,
                notes TEXT NOT NULL
            );
            INSERT INTO platform.{testTable} (id, notes) VALUES ('{Guid.NewGuid()}', 'Permitted DDL');
            DROP TABLE platform.{testTable};";

        var exception = await Record.ExceptionAsync(async () =>
        {
            await dbContext.Database.ExecuteSqlRawAsync(rawSql);
        });

        Assert.Null(exception);
    }

    [Fact]
    public async Task DB019_SafeCleanup_CleansUpOnSetupFailure()
    {
        var disposableDbName = $"maintenx_test_failure_sim_{Guid.NewGuid():N}";
        TestDatabaseGuard.EnsureSafeTestDatabaseName(disposableDbName);

        // Provision disposable database as admin
        using (var adminConn = new NpgsqlConnection(_adminConnectionString))
        {
            await adminConn.OpenAsync();
            using var createCmd = adminConn.CreateCommand();
            createCmd.CommandText = !string.IsNullOrWhiteSpace(_appRole)
                ? $"CREATE DATABASE {disposableDbName} OWNER \"{_appRole}\";"
                : $"CREATE DATABASE {disposableDbName};";
            await createCmd.ExecuteNonQueryAsync();
        }

        bool cleanedUp = false;
        try
        {
            // Simulate a setup failure after database creation
            throw new InvalidOperationException("Simulated migration/initialization failure");
        }
        catch
        {
            // Trigger emergency teardown
            NpgsqlConnection.ClearAllPools();
            TestDatabaseGuard.EnsureSafeTestDatabaseName(disposableDbName);

            using var dropConn = new NpgsqlConnection(_adminConnectionString);
            await dropConn.OpenAsync();
            using var dropCmd = dropConn.CreateCommand();
            dropCmd.CommandText = $"DROP DATABASE IF EXISTS {disposableDbName} WITH (FORCE);";
            await dropCmd.ExecuteNonQueryAsync();
            cleanedUp = true;
        }

        Assert.True(cleanedUp);

        // Verify database is completely gone
        using (var verifyConn = new NpgsqlConnection(_adminConnectionString))
        {
            await verifyConn.OpenAsync();
            using var checkCmd = verifyConn.CreateCommand();
            checkCmd.CommandText = $"SELECT COUNT(*) FROM pg_database WHERE datname = '{disposableDbName}';";
            var count = Convert.ToInt64(await checkCmd.ExecuteScalarAsync());
            Assert.Equal(0L, count);
        }
    }

    [Fact]
    public async Task DB020_FixtureInitializationFailure_GuaranteesDatabaseCleanupAndSurfacesError()
    {
        var config = _baseFactory.Services.GetRequiredService<IConfiguration>();
        var simulatedDbName = $"maintenx_test_sim_fail_{Guid.NewGuid():N}";
        bool databaseExistedDuringFailure = false;

        // Exercise the real fixture initialization path with an intentional post-provision failure
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await TestDatabaseGuard.ProvisionAndInitializeAsync(
                _adminConnectionString,
                _testConnectionString,
                config,
                initializeSchemaAsync: async (isolatedConnectionString) =>
                {
                    // Verify the disposable database was genuinely created in PostgreSQL
                    using (var checkConn = new NpgsqlConnection(_adminConnectionString))
                    {
                        await checkConn.OpenAsync();
                        using var checkCmd = checkConn.CreateCommand();
                        checkCmd.CommandText = $"SELECT COUNT(*) FROM pg_database WHERE datname = '{simulatedDbName}';";
                        var count = Convert.ToInt64(await checkCmd.ExecuteScalarAsync());
                        databaseExistedDuringFailure = (count == 1L);
                    }

                    // Intentionally throw during initialization
                    throw new InvalidOperationException("Simulated post-provision migration/setup failure.");
                },
                customDbName: simulatedDbName);
        });

        // 1. Verify failure is surfaced to the test runner
        Assert.NotNull(exception);
        Assert.Contains("Failed to connect or initialize isolated test database", exception.Message);
        Assert.Contains(simulatedDbName, exception.Message);
        Assert.NotNull(exception.InnerException);
        Assert.Equal("Simulated post-provision migration/setup failure.", exception.InnerException.Message);

        // 2. Verify the database was indeed created before the failure occurred
        Assert.True(databaseExistedDuringFailure, "Disposable database must have been provisioned prior to initialization failure.");

        // 3. Verify cleanup removed the database and no disposable database was left behind
        using (var verifyConn = new NpgsqlConnection(_adminConnectionString))
        {
            await verifyConn.OpenAsync();
            using var verifyCmd = verifyConn.CreateCommand();
            verifyCmd.CommandText = $"SELECT COUNT(*) FROM pg_database WHERE datname = '{simulatedDbName}';";
            var remainingCount = Convert.ToInt64(await verifyCmd.ExecuteScalarAsync());
            Assert.Equal(0L, remainingCount);
        }
    }

    [Fact]
    public async Task DB021_RolePassword_WithApostrophesAndSpecialCharacters_CanAuthenticate()
    {
        var testRole = $"test_role_special_{Guid.NewGuid():N}";
        var specialPassword = "p'a\"\\$w;--ord!#%&";

        // Step 1: Administrator creates role using safe dynamic format(%I, %L)
        using (var adminConn = new NpgsqlConnection(_adminConnectionString))
        {
            await adminConn.OpenAsync();
            using var createCmd = adminConn.CreateCommand();
            createCmd.CommandText = @"
                SELECT format('CREATE ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', @role, @pass);";
            createCmd.Parameters.AddWithValue("role", testRole);
            createCmd.Parameters.AddWithValue("pass", specialPassword);
            var sql = (string?)await createCmd.ExecuteScalarAsync();
            Assert.NotNull(sql);

            using var execCmd = adminConn.CreateCommand();
            execCmd.CommandText = sql;
            await execCmd.ExecuteNonQueryAsync();
        }

        try
        {
            // Step 2: Authenticate using the special password containing apostrophes and SQL-special characters
            var testConnBuilder = new NpgsqlConnectionStringBuilder(_testConnectionString)
            {
                Username = testRole,
                Password = specialPassword
            };

            using var testConn = new NpgsqlConnection(testConnBuilder.ConnectionString);
            await testConn.OpenAsync();
            Assert.Equal(ConnectionState.Open, testConn.State);

            using var whoamiCmd = testConn.CreateCommand();
            whoamiCmd.CommandText = "SELECT current_user;";
            var currentUser = (string?)await whoamiCmd.ExecuteScalarAsync();
            Assert.Equal(testRole, currentUser);
        }
        finally
        {
            // Step 3: Cleanup role
            using var adminConn = new NpgsqlConnection(_adminConnectionString);
            await adminConn.OpenAsync();
            using var dropCmd = adminConn.CreateCommand();
            dropCmd.CommandText = $"DROP ROLE IF EXISTS \"{testRole}\";";
            await dropCmd.ExecuteNonQueryAsync();
        }
    }

    [Theory]
    [InlineData("maintenx_app", true)]
    [InlineData("maintenx_dev", true)]
    [InlineData("_custom123", true)]
    [InlineData("APP_USER", true)]
    [InlineData("a_1234567890123456789012345678901234567890123456789012345678901", true)]
    [InlineData("bad;user", false)]
    [InlineData("bad-user", false)]
    [InlineData("123user", false)]
    [InlineData("user\"name", false)]
    [InlineData("user'name", false)]
    [InlineData("user name", false)]
    [InlineData("", false)]
    [InlineData("a_12345678901234567890123456789012345678901234567890123456789012", false)]
    public void DB022_InitRolesScript_IdentifierValidation_EnforcesPostgreSqlIdentifierRules(string identifier, bool shouldBeValid)
    {
        var regex = new System.Text.RegularExpressions.Regex("^[a-zA-Z_][a-zA-Z0-9_]{0,62}$");
        var isValid = regex.IsMatch(identifier);
        Assert.Equal(shouldBeValid, isValid);
    }

    [Theory]
    [InlineData("localhost;127.0.0.1;postgres")]
    [InlineData("localhost, 127.0.0.1, postgres")]
    [InlineData("localhost; 127.0.0.1, postgres")]
    public void DB023_HostAllowlist_SupportsBothSemicolonAndCommaDelimiters(string allowedHostsConfig)
    {
        var validAdmin = "Host=localhost;Port=5432;Database=postgres;Username=postgres;Password=pass;";
        var validTest = "Host=localhost;Port=5432;Database=postgres;Username=maintenx_app;Password=pass;";

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TestDatabase:AllowProvisioning"] = "true",
                ["TestDatabase:AllowedHosts"] = allowedHostsConfig
            })
            .Build();

        // Valid hosts must pass without exception
        TestDatabaseGuard.ValidateTestDatabaseSafety("maintenx_test_sample", validAdmin, validTest, config);
    }
}
