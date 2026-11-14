namespace MaintenX.Api.Configuration;

using Microsoft.Extensions.Options;

/// <summary>
/// Fail-fast validator for <see cref="RateLimitingOptions"/>.
/// Validates permit limits, window durations, segment divisibility, and partition memory bounds on application boot.
/// </summary>
public sealed class RateLimitingOptionsValidator : IValidateOptions<RateLimitingOptions>
{
    public ValidateOptionsResult Validate(string? name, RateLimitingOptions options)
    {
        var failures = new List<string>();

        if (options.RegistrationPermitLimit <= 0)
        {
            failures.Add($"Invalid 'RateLimiting:RegistrationPermitLimit': {options.RegistrationPermitLimit}. Permit limit must be greater than zero.");
        }

        if (options.LoginPermitLimit <= 0)
        {
            failures.Add($"Invalid 'RateLimiting:LoginPermitLimit': {options.LoginPermitLimit}. Permit limit must be greater than zero.");
        }

        if (options.RefreshPermitLimit <= 0)
        {
            failures.Add($"Invalid 'RateLimiting:RefreshPermitLimit': {options.RefreshPermitLimit}. Permit limit must be greater than zero.");
        }

        if (options.WindowSeconds <= 0)
        {
            failures.Add($"Invalid 'RateLimiting:WindowSeconds': {options.WindowSeconds}. Window duration must be greater than zero seconds.");
        }

        if (options.SegmentsPerWindow <= 0)
        {
            failures.Add($"Invalid 'RateLimiting:SegmentsPerWindow': {options.SegmentsPerWindow}. Segments count must be greater than zero.");
        }

        if (options.MaxTrackedPartitions <= 0)
        {
            failures.Add($"Invalid 'RateLimiting:MaxTrackedPartitions': {options.MaxTrackedPartitions}. Maximum tracked partitions must be greater than zero.");
        }

        // Compatibility checks between WindowSeconds and SegmentsPerWindow for sliding-window rate limiters
        if (options.WindowSeconds > 0 && options.SegmentsPerWindow > 0)
        {
            if (options.SegmentsPerWindow > options.WindowSeconds)
            {
                failures.Add($"Invalid rate limiting segment configuration: 'SegmentsPerWindow' ({options.SegmentsPerWindow}) cannot exceed 'WindowSeconds' ({options.WindowSeconds}). Segment duration must be at least 1 second.");
            }
            else if (options.WindowSeconds % options.SegmentsPerWindow != 0)
            {
                failures.Add($"Invalid rate limiting segment configuration: 'WindowSeconds' ({options.WindowSeconds}) must be evenly divisible by 'SegmentsPerWindow' ({options.SegmentsPerWindow}) for deterministic segment boundaries.");
            }
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}

