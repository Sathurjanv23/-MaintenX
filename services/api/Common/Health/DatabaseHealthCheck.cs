using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace MaintenX.Api.Common.Health;

/// <summary>
/// Verifies actual PostgreSQL database connectivity for readiness probes.
/// Will accurately fail if PostgreSQL is down or unreachable.
/// </summary>
public sealed class DatabaseHealthCheck : IHealthCheck
{
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
            return HealthCheckResult.Unhealthy("PostgreSQL connection string 'DefaultConnection' is missing or empty.");
        }

        try
        {
            // Build connection string with short connection timeout to avoid hanging health probes
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
                return HealthCheckResult.Healthy("PostgreSQL connection is healthy and responsive.");
            }

            return HealthCheckResult.Unhealthy("PostgreSQL responded with an unexpected query result.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "PostgreSQL readiness health check failed: {ErrorMessage}", ex.Message);
            return HealthCheckResult.Unhealthy($"PostgreSQL connection failed: {ex.Message}", ex);
        }
    }
}

