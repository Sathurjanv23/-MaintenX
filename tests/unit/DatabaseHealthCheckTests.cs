using MaintenX.Api.Common.Health;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace MaintenX.UnitTests;

public class DatabaseHealthCheckTests
{
    [Fact]
    public async Task CheckHealthAsync_WhenConnectionStringMissing_ReturnsSafeUnhealthyMessage()
    {
        // Arrange
        var inMemorySettings = new Dictionary<string, string?>();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
            .Build();

        var healthCheck = new DatabaseHealthCheck(
            configuration,
            NullLogger<DatabaseHealthCheck>.Instance);

        var context = new HealthCheckContext
        {
            Registration = new HealthCheckRegistration("postgresql", healthCheck, null, null)
        };

        // Act
        var result = await healthCheck.CheckHealthAsync(context);

        // Assert - Verifies secure generic public error message
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("Database service is unavailable.", result.Description);
    }

    [Fact]
    public async Task CheckHealthAsync_WhenConnectionStringInvalidHost_ReturnsSafeUnhealthyMessageWithoutLeakingDetails()
    {
        // Arrange - point to non-routable host to simulate DB failure
        var inMemorySettings = new Dictionary<string, string?>
        {
            { "ConnectionStrings:DefaultConnection", "Host=127.0.0.1;Port=59999;Database=fake;Username=fake;Password=fake;Timeout=1;" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
            .Build();

        var healthCheck = new DatabaseHealthCheck(
            configuration,
            NullLogger<DatabaseHealthCheck>.Instance);

        var context = new HealthCheckContext
        {
            Registration = new HealthCheckRegistration("postgresql", healthCheck, null, null)
        };

        // Act
        var result = await healthCheck.CheckHealthAsync(context);

        // Assert - Verifies unhandled DB exceptions do not leak raw exception messages
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Equal("Database service is unavailable.", result.Description);
        Assert.DoesNotContain("59999", result.Description);
        Assert.DoesNotContain("fake", result.Description);
    }
}
