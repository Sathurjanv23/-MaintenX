namespace MaintenX.Api.Configuration;

/// <summary>
/// Strongly typed configuration options for trusted reverse proxies and forwarded headers.
/// </summary>
public sealed class TrustedProxyOptions
{
    public const string SectionName = "TrustedProxies";

    /// <summary>
    /// Explicit list of trusted reverse proxy IP addresses (e.g. "10.0.0.1", "127.0.0.1").
    /// </summary>
    public List<string> KnownProxies { get; set; } = [];

    /// <summary>
    /// Explicit list of trusted reverse proxy CIDR network blocks (e.g. "10.0.0.0/8", "172.16.0.0/12").
    /// </summary>
    public List<string> KnownNetworks { get; set; } = [];

    /// <summary>
    /// Maximum number of proxy hops to process from X-Forwarded-For headers.
    /// Defaults to 1 to prevent client spoofing through upstream header chains.
    /// </summary>
    public int ForwardLimit { get; set; } = 1;
}

