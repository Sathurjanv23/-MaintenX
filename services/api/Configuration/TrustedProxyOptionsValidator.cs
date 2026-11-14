namespace MaintenX.Api.Configuration;

using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

/// <summary>
/// Fail-fast validator for <see cref="TrustedProxyOptions"/>.
/// Ensures that production environments strictly define an explicit trusted-proxy allowlist,
/// and that all configured proxy IP addresses and CIDR network blocks parse cleanly.
/// </summary>
public sealed class TrustedProxyOptionsValidator : IValidateOptions<TrustedProxyOptions>
{
    private readonly IHostEnvironment _environment;

    public TrustedProxyOptionsValidator(IHostEnvironment environment)
    {
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
    }

    public ValidateOptionsResult Validate(string? name, TrustedProxyOptions options)
    {
        var failures = new List<string>();

        if (options.ForwardLimit <= 0)
        {
            failures.Add($"Invalid ForwardLimit: {options.ForwardLimit}. ForwardLimit must be at least 1.");
        }

        // Validate KnownProxies
        if (options.KnownProxies is { Count: > 0 })
        {
            foreach (var proxy in options.KnownProxies)
            {
                if (string.IsNullOrWhiteSpace(proxy))
                {
                    failures.Add("Trusted proxy IP list contains an empty or whitespace entry.");
                    continue;
                }

                if (!IPAddress.TryParse(proxy.Trim(), out _))
                {
                    failures.Add($"Invalid trusted proxy IP address: '{proxy}'.");
                }
            }
        }

        // Validate KnownNetworks
        if (options.KnownNetworks is { Count: > 0 })
        {
            foreach (var network in options.KnownNetworks)
            {
                if (string.IsNullOrWhiteSpace(network))
                {
                    failures.Add("Trusted proxy network list contains an empty or whitespace entry.");
                    continue;
                }

                if (!System.Net.IPNetwork.TryParse(network.Trim(), out _))
                {
                    failures.Add($"Invalid trusted proxy CIDR network block: '{network}'. Expected format: '10.0.0.0/8' or '172.16.0.0/12'.");
                }
            }
        }

        // In Production, fail fast if the allowlist is completely empty
        if (_environment.IsProduction())
        {
            var totalCount = (options.KnownProxies?.Count ?? 0) + (options.KnownNetworks?.Count ?? 0);
            if (totalCount == 0)
            {
                failures.Add(
                    "Production security violation: Missing trusted proxy configuration. " +
                    "Production environments require an explicit allowlist in 'TrustedProxies:KnownProxies' or 'TrustedProxies:KnownNetworks' " +
                    "to prevent client IP spoofing and untrusted forwarded header processing.");
            }
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}

