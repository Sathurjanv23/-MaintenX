namespace MaintenX.UnitTests.Security;

using MaintenX.Api.Common.Security;
using MaintenX.Api.Configuration;
using Xunit;

public class RateLimitingConfigurationTests
{
    [Fact]
    public void RateLimitingOptions_HasExpectedDefaultPermits()
    {
        var options = new RateLimitingOptions();

        Assert.Equal(5, options.RegistrationPermitLimit);
        Assert.Equal(10, options.LoginPermitLimit);
        Assert.Equal(30, options.RefreshPermitLimit);
        Assert.Equal(60, options.WindowSeconds);
        Assert.Equal(6, options.SegmentsPerWindow);
    }

    [Fact]
    public void AuthRateLimitPolicies_ExposesStandardPolicyNames()
    {
        Assert.Equal("Auth.Registration", AuthRateLimitPolicies.Registration);
        Assert.Equal("Auth.Login", AuthRateLimitPolicies.Login);
        Assert.Equal("Auth.Refresh", AuthRateLimitPolicies.Refresh);
    }
}

