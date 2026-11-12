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
    public async Task Get_HealthReady_WhenDatabaseIsUnreachable_ReturnsServiceUnavailableAndUnhealthyStatus()
    {
        // Arrange
        var client = _factory.CreateClient();

        // Act
        // Because Docker DB is not running during standalone test, readiness probe must accurately reflect this
        var response = await client.GetAsync("/health/ready");

        // Assert: AC-006: API readiness accurately reflects DB health (503 ServiceUnavailable)
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        using var jsonDoc = JsonDocument.Parse(content);
        var root = jsonDoc.RootElement;

        Assert.Equal("Unhealthy", root.GetProperty("status").GetString());
        Assert.True(root.TryGetProperty("checks", out var checks));
        Assert.True(checks.GetArrayLength() > 0);

        var dbCheck = checks.EnumerateArray().FirstOrDefault(c => c.GetProperty("component").GetString() == "postgresql");
        Assert.Equal("Unhealthy", dbCheck.GetProperty("status").GetString());
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

