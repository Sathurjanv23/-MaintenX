namespace MaintenX.UnitTests.Security;

using MaintenX.Api.Configuration;
using Xunit;

public class RateLimitingOptionsValidatorTests
{
    private readonly RateLimitingOptionsValidator _validator = new();

    [Fact]
    public void Validate_WithValidOptions_Succeeds()
    {
        var options = new RateLimitingOptions
        {
            RegistrationPermitLimit = 5,
            LoginPermitLimit = 10,
            RefreshPermitLimit = 30,
            WindowSeconds = 60,
            SegmentsPerWindow = 6,
            MaxTrackedPartitions = 10_000
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithInvalidRegistrationPermitLimit_Fails(int limit)
    {
        var options = new RateLimitingOptions { RegistrationPermitLimit = limit };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("RegistrationPermitLimit"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithInvalidLoginPermitLimit_Fails(int limit)
    {
        var options = new RateLimitingOptions { LoginPermitLimit = limit };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("LoginPermitLimit"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithInvalidRefreshPermitLimit_Fails(int limit)
    {
        var options = new RateLimitingOptions { RefreshPermitLimit = limit };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("RefreshPermitLimit"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithInvalidWindowSeconds_Fails(int seconds)
    {
        var options = new RateLimitingOptions { WindowSeconds = seconds };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("WindowSeconds"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithInvalidSegmentsPerWindow_Fails(int segments)
    {
        var options = new RateLimitingOptions { SegmentsPerWindow = segments };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("SegmentsPerWindow"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithInvalidMaxTrackedPartitions_Fails(int partitions)
    {
        var options = new RateLimitingOptions { MaxTrackedPartitions = partitions };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("MaxTrackedPartitions"));
    }

    [Fact]
    public void Validate_WithSegmentsPerWindowExceedingWindowSeconds_Fails()
    {
        // 70 segments in a 60-second window -> segment duration < 1s
        var options = new RateLimitingOptions
        {
            WindowSeconds = 60,
            SegmentsPerWindow = 70
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("cannot exceed 'WindowSeconds'"));
    }

    [Fact]
    public void Validate_WithWindowSecondsNotDivisibleBySegmentsPerWindow_Fails()
    {
        // 60 seconds is not evenly divisible by 7 segments
        var options = new RateLimitingOptions
        {
            WindowSeconds = 60,
            SegmentsPerWindow = 7
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("must be evenly divisible"));
    }
}

