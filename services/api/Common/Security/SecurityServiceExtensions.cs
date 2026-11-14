namespace MaintenX.Api.Common.Security;

using System.Net;
using System.Threading.RateLimiting;
using MaintenX.Api.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Service and middleware registration extensions for MaintenX security infrastructure.
/// Configures JWT options, cryptographic key ring, trusted reverse proxy forwarded headers,
/// memory-bounded rate limiting, and the authoritative security middleware pipeline.
/// </summary>
public static class SecurityServiceExtensions
{
    /// <summary>
    /// Registers security configuration, JWT authentication, authorization, trusted proxy handling,
    /// and rate limiting services into the DI container without creating intermediate ServiceProviders.
    /// </summary>
    public static IServiceCollection AddMaintenXSecurity(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        // 1. Core TimeProvider (Injectable for deterministic testing)
        services.TryAddSingleton(TimeProvider.System);

        // 2. JWT Configuration & Key Ring
        services.AddSingleton<IValidateOptions<JwtOptions>, JwtOptionsValidator>();
        services.AddOptions<JwtOptions>()
            .Bind(configuration.GetSection(JwtOptions.SectionName))
            .ValidateOnStart();

        services.AddSingleton<IJwtKeyRing, JwtKeyRing>();

        // 3. Trusted Proxy & Forwarded Headers Configuration
        services.AddSingleton<IValidateOptions<TrustedProxyOptions>, TrustedProxyOptionsValidator>();
        services.AddOptions<TrustedProxyOptions>()
            .Bind(configuration.GetSection(TrustedProxyOptions.SectionName))
            .ValidateOnStart();

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

            // Clear default known proxies and networks to prevent trusting arbitrary or unconfigured defaults
            options.KnownProxies.Clear();
            options.KnownNetworks.Clear();

            var proxyConfig = configuration.GetSection(TrustedProxyOptions.SectionName).Get<TrustedProxyOptions>()
                              ?? new TrustedProxyOptions();

            options.ForwardLimit = proxyConfig.ForwardLimit > 0 ? proxyConfig.ForwardLimit : 1;

            if (proxyConfig.KnownProxies is { Count: > 0 })
            {
                foreach (var proxy in proxyConfig.KnownProxies)
                {
                    if (IPAddress.TryParse(proxy.Trim(), out var ip))
                    {
                        options.KnownProxies.Add(ip);
                    }
                }
            }

            if (proxyConfig.KnownNetworks is { Count: > 0 })
            {
                foreach (var network in proxyConfig.KnownNetworks)
                {
                    if (System.Net.IPNetwork.TryParse(network.Trim(), out var net))
                    {
                        options.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(net.BaseAddress, net.PrefixLength));
                    }
                }
            }

            // In development and test environments, if no proxies or networks were specified, allow loopback
            if (!environment.IsProduction() && options.KnownProxies.Count == 0 && options.KnownNetworks.Count == 0)
            {
                options.KnownProxies.Add(IPAddress.Loopback);
                options.KnownProxies.Add(IPAddress.IPv6Loopback);
            }
        });

        // 4. JWT Authentication & Bearer Token Validation (DI-aware options, zero BuildServiceProvider)
        services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>();
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer();

        services.AddAuthorization();

        // 5. Memory-Bounded Rate Limiting Infrastructure
        services.Configure<RateLimitingOptions>(configuration.GetSection(RateLimitingOptions.SectionName));

        services.AddSingleton<BoundedPartitionTracker>(sp =>
        {
            var rateOptions = sp.GetRequiredService<IOptions<RateLimitingOptions>>().Value;
            var timeProvider = sp.GetRequiredService<TimeProvider>();
            return new BoundedPartitionTracker(
                rateOptions.MaxTrackedPartitions,
                TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                timeProvider);
        });

        services.AddRateLimiter(limiterOptions =>
        {
            var rateOptions = configuration.GetSection(RateLimitingOptions.SectionName).Get<RateLimitingOptions>()
                              ?? new RateLimitingOptions();

            limiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            limiterOptions.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.ContentType = "application/problem+json";

                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter = ((int)Math.Max(1, retryAfter.TotalSeconds)).ToString();
                }
                else
                {
                    context.HttpContext.Response.Headers.RetryAfter = rateOptions.WindowSeconds.ToString();
                }

                var problemDetails = new ProblemDetails
                {
                    Status = StatusCodes.Status429TooManyRequests,
                    Title = "Too Many Requests",
                    Detail = "Rate limit exceeded. Please try again later.",
                    Instance = context.HttpContext.Request.Path,
                    Extensions =
                    {
                        ["traceId"] = context.HttpContext.TraceIdentifier,
                        ["timestamp"] = DateTimeOffset.UtcNow
                    }
                };

                await context.HttpContext.Response.WriteAsJsonAsync(
                    problemDetails,
                    options: (System.Text.Json.JsonSerializerOptions?)null,
                    contentType: "application/problem+json",
                    cancellationToken: cancellationToken);
            };

            // Policy: Auth.Registration (Default 5 req/min/IP)
            limiterOptions.AddPolicy(AuthRateLimitPolicies.Registration, httpContext =>
            {
                var partitionTracker = httpContext.RequestServices.GetRequiredService<BoundedPartitionTracker>();
                var clientIp = ResolveClientIp(httpContext);
                var partitionKey = partitionTracker.ResolvePartitionKey("registration", clientIp);

                if (partitionKey.StartsWith("unresolved_", StringComparison.Ordinal) ||
                    partitionKey.StartsWith("overflow_", StringComparison.Ordinal))
                {
                    return RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey,
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 1,
                            Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                            QueueLimit = 0
                        });
                }

                return RateLimitPartition.GetSlidingWindowLimiter(
                    partitionKey,
                    _ => new SlidingWindowRateLimiterOptions
                    {
                        PermitLimit = rateOptions.RegistrationPermitLimit,
                        Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                        SegmentsPerWindow = rateOptions.SegmentsPerWindow,
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });

            // Policy: Auth.Login (Default 10 req/min/IP)
            limiterOptions.AddPolicy(AuthRateLimitPolicies.Login, httpContext =>
            {
                var partitionTracker = httpContext.RequestServices.GetRequiredService<BoundedPartitionTracker>();
                var clientIp = ResolveClientIp(httpContext);
                var partitionKey = partitionTracker.ResolvePartitionKey("login", clientIp);

                if (partitionKey.StartsWith("unresolved_", StringComparison.Ordinal) ||
                    partitionKey.StartsWith("overflow_", StringComparison.Ordinal))
                {
                    return RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey,
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 1,
                            Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                            QueueLimit = 0
                        });
                }

                return RateLimitPartition.GetSlidingWindowLimiter(
                    partitionKey,
                    _ => new SlidingWindowRateLimiterOptions
                    {
                        PermitLimit = rateOptions.LoginPermitLimit,
                        Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                        SegmentsPerWindow = rateOptions.SegmentsPerWindow,
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });

            // Policy: Auth.Refresh (Default 30 req/min/IP)
            limiterOptions.AddPolicy(AuthRateLimitPolicies.Refresh, httpContext =>
            {
                var partitionTracker = httpContext.RequestServices.GetRequiredService<BoundedPartitionTracker>();
                var clientIp = ResolveClientIp(httpContext);
                var partitionKey = partitionTracker.ResolvePartitionKey("refresh", clientIp);

                if (partitionKey.StartsWith("unresolved_", StringComparison.Ordinal) ||
                    partitionKey.StartsWith("overflow_", StringComparison.Ordinal))
                {
                    return RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey,
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 1,
                            Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                            QueueLimit = 0
                        });
                }

                return RateLimitPartition.GetSlidingWindowLimiter(
                    partitionKey,
                    _ => new SlidingWindowRateLimiterOptions
                    {
                        PermitLimit = rateOptions.RefreshPermitLimit,
                        Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                        SegmentsPerWindow = rateOptions.SegmentsPerWindow,
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });
        });

        return services;
    }

    /// <summary>
    /// Configures the authoritative MaintenX security middleware pipeline in strict order:
    /// 1. RateLimiter (enforces IP-based rate limiting before authentication)
    /// 2. Authentication (validates JWT Bearer tokens)
    /// 3. Authorization (enforces security policies)
    /// Note: app.UseForwardedHeaders() must execute at the front of the pipeline before CORS
    /// and exception handling so RemoteIpAddress and request scheme are resolved.
    /// </summary>
    public static WebApplication UseMaintenXSecurity(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();

        return app;
    }

    private static IPAddress? ResolveClientIp(HttpContext httpContext)
    {
        return httpContext.Connection.RemoteIpAddress;
    }

    /// <summary>
    /// DI-aware post-configure options for <see cref="JwtBearerOptions"/>.
    /// Eliminates intermediate BuildServiceProvider by resolving IJwtKeyRing directly from DI.
    /// </summary>
    private sealed class JwtBearerPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>
    {
        private readonly IJwtKeyRing _keyRing;
        private readonly IOptions<JwtOptions> _jwtOptions;
        private readonly IHostEnvironment _environment;

        public JwtBearerPostConfigureOptions(
            IJwtKeyRing keyRing,
            IOptions<JwtOptions> jwtOptions,
            IHostEnvironment environment)
        {
            _keyRing = keyRing;
            _jwtOptions = jwtOptions;
            _environment = environment;
        }

        public void PostConfigure(string? name, JwtBearerOptions options)
        {
            var jwt = _jwtOptions.Value;

            options.RequireHttpsMetadata = _environment.IsProduction();
            options.SaveToken = false;

            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwt.Issuer,
                ValidateAudience = true,
                ValidAudience = jwt.Audience,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                ClockSkew = TimeSpan.Zero,
                ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                {
                    if (string.IsNullOrWhiteSpace(kid))
                    {
                        throw new SecurityTokenException("Missing required 'kid' header in JWT.");
                    }

                    if (_keyRing.TryGetKey(kid, out var key) && key != null)
                    {
                        return [key];
                    }

                    throw new SecurityTokenException($"Unknown or untrusted 'kid': '{kid}'.");
                }
            };

            options.Events = new JwtBearerEvents
            {
                OnChallenge = async context =>
                {
                    context.HandleResponse();
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "application/problem+json";

                    var problemDetails = new ProblemDetails
                    {
                        Status = StatusCodes.Status401Unauthorized,
                        Title = "Unauthorized",
                        Detail = "Access to this resource requires valid JWT Bearer authentication.",
                        Instance = context.Request.Path,
                        Extensions =
                        {
                            ["traceId"] = context.HttpContext.TraceIdentifier,
                            ["timestamp"] = DateTimeOffset.UtcNow
                        }
                    };

                    await context.Response.WriteAsJsonAsync(
                        problemDetails,
                        options: (System.Text.Json.JsonSerializerOptions?)null,
                        contentType: "application/problem+json",
                        cancellationToken: context.HttpContext.RequestAborted);
                }
            };
        }
    }
}
