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
/// Integration test suite for MaintenX PostgreSQL Database Foundation (FEAT-001).
/// All test cases execute against an isolated disposable database ('maintenx_test_*')
/// with strict safety guards to protect development, staging, and production databases.
/// </summary>
public class DatabaseFoundationIntegrationTests : IClassFixture<WebApplicationFactory<Program>>, IAsyncLifetime
{
    private readonly WebApplicationFactory<Program> _baseFactory;
    private WebApplicationFactory<Program> _isolatedFactory = null!;
    private string _adminConnectionString = string.Empty;
    private string _testDbName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public DatabaseFoundationIntegrationTests(WebApplicationFactory<Program> baseFactory)
    {
        _baseFactory = baseFactory;
    }

    /// <summary>
    /// Strict safety guard preventing destruction or operations on non-test databases.
    /// </summary>
    internal static void EnsureSafeTestDatabaseName(string databaseName)
    {
        if (string.IsNullOrWhiteSpace(databaseName) ||
            !databaseName.StartsWith("maintenx_test_", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Safety violation: Refusing to operate on database '{databaseName}'. " +
                "Automated test database operations are strictly restricted to databases prefixed with 'maintenx_test_'.");
        }

        string[] protectedDatabases = ["maintenx_dev", "maintenx_prod", "maintenx_staging", "postgres", "template1"];
        if (protectedDatabases.Any(p => p.Equals(databaseName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"Safety violation: Cannot drop or mutate protected database '{databaseName}'.");
        }
    }

    public async Task InitializeAsync()
    {
        var config = _baseFactory.Services.GetRequiredService<IConfiguration>();
        var baseConnection = config.GetConnectionString("TestConnection")
            ?? Environment.GetEnvironmentVariable("ConnectionStrings__TestConnection")
            ?? config.GetConnectionString("DefaultConnection")
            ?? Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection")
            ?? throw new InvalidOperationException(
                "Database integration testing requires an accessible PostgreSQL connection string configured via " +
                "'ConnectionStrings:TestConnection', 'ConnectionStrings:DefaultConnection', or environment variables.");

        var adminConnection = config.GetConnectionString("AdminConnection")
            ?? Environment.GetEnvironmentVariable("ConnectionStrings__AdminConnection");

        _adminConnectionString = !string.IsNullOrWhiteSpace(adminConnection)
            ? adminConnection
            : new NpgsqlConnectionStringBuilder(baseConnection) { Database = "postgres" }.ConnectionString;

        // Generate isolated disposable database name with strict 'maintenx_test_' prefix
        _testDbName = $"maintenx_test_{Guid.NewGuid():N}";
        EnsureSafeTestDatabaseName(_testDbName);

        bool databaseCreated = false;
        try
        {
            // Provision the clean isolated database using admin credentials on PostgreSQL
            using (var adminConn = new NpgsqlConnection(_adminConnectionString))
            {
                await adminConn.OpenAsync();
                using var createCmd = adminConn.CreateCommand();
                createCmd.CommandText = $"CREATE DATABASE {_testDbName};";
                await createCmd.ExecuteNonQueryAsync();
                databaseCreated = true;
            }

            // Build isolated connection string targeting the disposable database
            var isolatedBuilder = new NpgsqlConnectionStringBuilder(baseConnection)
            {
                Database = _testDbName
            };
            _isolatedConnectionString = isolatedBuilder.ConnectionString;

            // Reconfigure WebApplicationFactory to strictly target the isolated test database
            _isolatedFactory = _baseFactory.WithWebHostBuilder(webBuilder =>
            {
                webBuilder.UseSetting("ConnectionStrings:DefaultConnection", _isolatedConnectionString);
            });

            // Apply all committed migrations to the isolated test database
            using var scope = _isolatedFactory.Services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();
            await dbContext.Database.MigrateAsync();
        }
        catch (Exception ex)
        {
            if (databaseCreated)
            {
                try
                {
                    NpgsqlConnection.ClearAllPools();
                    EnsureSafeTestDatabaseName(_testDbName);
                    using var cleanupConn = new NpgsqlConnection(_adminConnectionString);
                    await cleanupConn.OpenAsync();
                    using var dropCmd = cleanupConn.CreateCommand();
                    dropCmd.CommandText = $"DROP DATABASE IF EXISTS {_testDbName} WITH (FORCE);";
                    await dropCmd.ExecuteNonQueryAsync();
                }
                catch (Exception cleanupEx)
                {
                    throw new InvalidOperationException(
                        $"Failed to initialize isolated test database '{_testDbName}'. Immediate cleanup also failed: {cleanupEx.Message}",
                        new AggregateException(ex, cleanupEx));
                }
            }

            throw new InvalidOperationException(
                $"Database integration testing requires an accessible PostgreSQL instance. " +
                $"Failed to connect or initialize isolated test database '{_testDbName}'. Error: {ex.Message}", ex);
        }
    }

    public async Task DisposeAsync()
    {
        // Clear all connection pools before dropping the database
        NpgsqlConnection.ClearAllPools();

        if (!string.IsNullOrWhiteSpace(_testDbName) && !string.IsNullOrWhiteSpace(_adminConnectionString))
        {
            EnsureSafeTestDatabaseName(_testDbName);

            try
            {
                using var adminConn = new NpgsqlConnection(_adminConnectionString);
                await adminConn.OpenAsync();
                using var dropCmd = adminConn.CreateCommand();
                dropCmd.CommandText = $"DROP DATABASE IF EXISTS {_testDbName} WITH (FORCE);";
                await dropCmd.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[CRITICAL WARNING] Failed to drop disposable test database '{_testDbName}': {ex.Message}");
                throw;
            }
        }

        _isolatedFactory?.Dispose();
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
        EnsureSafeTestDatabaseName(disposableDbName);

        using (var adminConn = new NpgsqlConnection(_adminConnectionString))
        {
            await adminConn.OpenAsync();
            using var createCmd = adminConn.CreateCommand();
            createCmd.CommandText = $"CREATE DATABASE {disposableDbName};";
            await createCmd.ExecuteNonQueryAsync();
        }

        try
        {
            // Act: Build DbContext targeting the clean disposable database using application connection
            var testConnBuilder = new NpgsqlConnectionStringBuilder(_isolatedConnectionString)
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
            EnsureSafeTestDatabaseName(disposableDbName);

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
        EnsureSafeTestDatabaseName(disposableDbName);

        using (var adminConn = new NpgsqlConnection(_adminConnectionString))
        {
            await adminConn.OpenAsync();
            using var createCmd = adminConn.CreateCommand();
            createCmd.CommandText = $"CREATE DATABASE {disposableDbName};";
            await createCmd.ExecuteNonQueryAsync();
        }

        var testConnBuilder = new NpgsqlConnectionStringBuilder(_isolatedConnectionString)
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
            EnsureSafeTestDatabaseName(disposableDbName);

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
}
