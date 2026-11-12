using MaintenX.Api.Common.Health;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace MaintenX.UnitTests;

public class DatabaseHealthCheckTests
{
    [Fact]
    public async Task CheckHealthAsync_WhenConnectionStringMissing_ReturnsUnhealthy()
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

        // Assert
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("missing or empty", result.Description);
    }

    [Fact]
    public async Task CheckHealthAsync_WhenConnectionStringInvalidHost_ReturnsUnhealthyWithoutThrowing()
    {
        // Arrange - point to non-routable port to ensure immediate failure
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

        // Assert - Readiness must accurately report Unhealthy, never falsely claiming healthy
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("PostgreSQL connection failed", result.Description);
    }
}

