using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace MaintenX.Api.Common.Health;

/// <summary>
/// Verifies PostgreSQL database connectivity for readiness probes.
/// Enforces API security: returns safe generic public messages to clients
/// while recording granular exception diagnostics exclusively in server logs.
/// </summary>
public sealed class DatabaseHealthCheck : IHealthCheck
{
    private const string SafeHealthyMessage = "Database service is operational.";
    private const string SafeUnhealthyMessage = "Database service is unavailable.";

    private readonly IConfiguration _configuration;
    private readonly ILogger<DatabaseHealthCheck> _logger;

    public DatabaseHealthCheck(IConfiguration configuration, ILogger<DatabaseHealthCheck> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var connectionString = _configuration.GetConnectionString("DefaultConnection");

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            _logger.LogError("Database readiness check failed: 'DefaultConnection' configuration is missing or empty.");
            return HealthCheckResult.Unhealthy(SafeUnhealthyMessage);
        }

        try
        {
            // Use short connection timeout to prevent hanging readiness probes
            var csb = new NpgsqlConnectionStringBuilder(connectionString)
            {
                Timeout = 3,
                CommandTimeout = 3
            };

            await using var connection = new NpgsqlConnection(csb.ConnectionString);
            await connection.OpenAsync(cancellationToken);

            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT 1;";
            var result = await command.ExecuteScalarAsync(cancellationToken);

            if (result != null && Convert.ToInt32(result) == 1)
            {
                return HealthCheckResult.Healthy(SafeHealthyMessage);
            }

            _logger.LogWarning("PostgreSQL probe executed successfully but returned unexpected result: {Result}", result);
            return HealthCheckResult.Unhealthy(SafeUnhealthyMessage);
        }
        catch (Exception ex)
        {
            // Security: Log full exception detail internally, never leak connection strings or DB errors to callers
            _logger.LogError(ex, "PostgreSQL readiness probe exception: {ErrorMessage}", ex.Message);
            return HealthCheckResult.Unhealthy(SafeUnhealthyMessage);
        }
    }
}
