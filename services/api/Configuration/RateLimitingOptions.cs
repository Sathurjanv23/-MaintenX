namespace MaintenX.Api.Configuration;

/// <summary>
/// Strongly typed configuration options for authentication endpoint rate limiters.
/// These configure per-instance sliding window limits.
/// </summary>
public sealed class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    /// <summary>
    /// Registration endpoint permit limit per IP per minute. Defaults to 5.
    /// </summary>
    public int RegistrationPermitLimit { get; set; } = 5;

    /// <summary>
    /// Login endpoint permit limit per IP per minute. Defaults to 10.
    /// </summary>
    public int LoginPermitLimit { get; set; } = 10;

    /// <summary>
    /// Refresh endpoint permit limit per IP per minute. Defaults to 30.
    /// </summary>
    public int RefreshPermitLimit { get; set; } = 30;

    /// <summary>
    /// Sliding window duration in seconds. Defaults to 60 seconds (1 minute).
    /// </summary>
    public int WindowSeconds { get; set; } = 60;

    /// <summary>
    /// Number of segments per sliding window for memory-bounded cleanup. Defaults to 6 (10-second segments).
    /// </summary>
    public int SegmentsPerWindow { get; set; } = 6;
}

