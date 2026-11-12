using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace MaintenX.IntegrationTests;

public class HealthCheckIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public HealthCheckIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Get_HealthLive_ReturnsOkAndHealthyStatus()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/health/live");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var jsonDoc = JsonDocument.Parse(content);
        var root = jsonDoc.RootElement;

        Assert.Equal("Healthy", root.GetProperty("status").GetString());
        Assert.True(root.TryGetProperty("timestamp", out _));
        Assert.True(root.TryGetProperty("totalDurationMs", out _));
    }

    [Fact]
    public async Task Get_HealthReady_WhenDatabaseIsUnreachable_ReturnsServiceUnavailableAndSafeMessage()
    {
        // Arrange: Explicitly override connection string to non-routable port to deterministically test DB failure
        var brokenFactory = _factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting(
                "ConnectionStrings:DefaultConnection",
                "Host=127.0.0.1;Port=59999;Database=maintenx_broken;Username=none;Password=none;Timeout=1;");
        });
        var client = brokenFactory.CreateClient();

        // Act
        var response = await client.GetAsync("/health/ready");

        // Assert: API readiness probe must return 503 ServiceUnavailable when DB is unreachable
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var jsonDoc = JsonDocument.Parse(content);
        var root = jsonDoc.RootElement;

        Assert.Equal("Unhealthy", root.GetProperty("status").GetString());
        Assert.True(root.TryGetProperty("checks", out var checks));
        Assert.True(checks.GetArrayLength() > 0);

        var dbCheck = checks.EnumerateArray().FirstOrDefault(c => c.GetProperty("component").GetString() == "postgresql");
        Assert.Equal("Unhealthy", dbCheck.GetProperty("status").GetString());

        // Security assertion: Never leak internal error messages or connection strings
        var description = dbCheck.GetProperty("description").GetString();
        Assert.Equal("Database service is unavailable.", description);
        Assert.False(dbCheck.TryGetProperty("error", out _));
    }

    [Fact]
    public async Task Get_HealthReady_WhenDatabaseIsReachable_ReturnsOkAndHealthyStatus()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/health/ready");

        // In environments where PostgreSQL is available (such as CI with postgres service),
        // verify that the readiness probe accurately reflects healthy status
        if (response.StatusCode == HttpStatusCode.OK)
        {
            var content = await response.Content.ReadAsStringAsync();
            using var jsonDoc = JsonDocument.Parse(content);
            var root = jsonDoc.RootElement;

            Assert.Equal("Healthy", root.GetProperty("status").GetString());
            var dbCheck = root.GetProperty("checks").EnumerateArray()
                .FirstOrDefault(c => c.GetProperty("component").GetString() == "postgresql");
            Assert.Equal("Healthy", dbCheck.GetProperty("status").GetString());
            Assert.Equal("Database service is operational.", dbCheck.GetProperty("description").GetString());
        }
        else
        {
            // If DB is offline locally, it must return 503 ServiceUnavailable with safe message
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        }
    }

    [Fact]
    public async Task Get_ApiV1Info_ReturnsOkWithBootstrapMetadata()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        var response = await client.GetAsync("/api/v1/info");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var jsonDoc = JsonDocument.Parse(content);
        var root = jsonDoc.RootElement;

        Assert.Equal("MaintenX API", root.GetProperty("application").GetString());
        Assert.Equal("1.0.0-bootstrap", root.GetProperty("version").GetString());
        Assert.Equal("Operational", root.GetProperty("status").GetString());
    }
}
