namespace MaintenX.Api.Configuration;

/// <summary>
/// Strongly typed configuration options for database connectivity.
/// </summary>
public sealed class DatabaseOptions
{
    public const string SectionName = "ConnectionStrings";

    public string DefaultConnection { get; set; } = string.Empty;

    public int CommandTimeoutSeconds { get; set; } = 30;

    public int HealthCheckTimeoutSeconds { get; set; } = 3;
}

