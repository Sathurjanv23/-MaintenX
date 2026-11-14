namespace MaintenX.UnitTests.Security;

using MaintenX.Api.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Xunit;

public class TrustedProxyOptionsValidatorTests
{
    private sealed class MockHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "MaintenX.Api";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    [Fact]
    public void Validate_InProduction_WhenAllowlistIsEmpty_Fails()
    {
        var env = new MockHostEnvironment { EnvironmentName = Environments.Production };
        var validator = new TrustedProxyOptionsValidator(env);
        var options = new TrustedProxyOptions
        {
            KnownProxies = [],
            KnownNetworks = []
        };

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Production security violation"));
    }

    [Fact]
    public void Validate_InDevelopment_WhenAllowlistIsEmpty_Succeeds()
    {
        var env = new MockHostEnvironment { EnvironmentName = Environments.Development };
        var validator = new TrustedProxyOptionsValidator(env);
        var options = new TrustedProxyOptions
        {
            KnownProxies = [],
            KnownNetworks = []
        };

        var result = validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_WithValidIpAddressesAndNetworks_Succeeds()
    {
        var env = new MockHostEnvironment { EnvironmentName = Environments.Production };
        var validator = new TrustedProxyOptionsValidator(env);
        var options = new TrustedProxyOptions
        {
            KnownProxies = ["10.0.0.1", "127.0.0.1", "::1"],
            KnownNetworks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        };

        var result = validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_WithInvalidIpAddress_Fails()
    {
        var env = new MockHostEnvironment { EnvironmentName = Environments.Development };
        var validator = new TrustedProxyOptionsValidator(env);
        var options = new TrustedProxyOptions
        {
            KnownProxies = ["999.999.999.999"]
        };

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Invalid trusted proxy IP address"));
    }

    [Fact]
    public void Validate_WithInvalidCidrNetwork_Fails()
    {
        var env = new MockHostEnvironment { EnvironmentName = Environments.Development };
        var validator = new TrustedProxyOptionsValidator(env);
        var options = new TrustedProxyOptions
        {
            KnownNetworks = ["not-a-cidr-block"]
        };

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("Invalid trusted proxy CIDR network block"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_WithInvalidForwardLimit_Fails(int limit)
    {
        var env = new MockHostEnvironment { EnvironmentName = Environments.Development };
        var validator = new TrustedProxyOptionsValidator(env);
        var options = new TrustedProxyOptions
        {
            ForwardLimit = limit
        };

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("ForwardLimit must be at least 1"));
    }
}

