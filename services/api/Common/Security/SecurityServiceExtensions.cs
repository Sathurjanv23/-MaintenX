namespace MaintenX.Api.Common.Security;

using System.Net;
using System.Threading.RateLimiting;
using MaintenX.Api.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Service and middleware registration extensions for MaintenX security infrastructure.
/// Configures JWT options, cryptographic key ring, trusted reverse proxy forwarded headers,
/// and per-instance endpoint rate limiting.
/// </summary>
public static class SecurityServiceExtensions
{
    /// <summary>
    /// Registers security configuration, JWT authentication, authorization, trusted proxy handling,
    /// and rate limiting services into the DI container.
    /// </summary>
    public static IServiceCollection AddMaintenXSecurity(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        // 1. JWT Configuration & Key Ring
        services.AddSingleton<IValidateOptions<JwtOptions>, JwtOptionsValidator>();
        services.AddOptions<JwtOptions>()
            .Bind(configuration.GetSection(JwtOptions.SectionName))
            .ValidateOnStart();

        services.AddSingleton<IJwtKeyRing, JwtKeyRing>();

        // 2. Trusted Proxy & Forwarded Headers Configuration
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

        // 3. JWT Authentication & Bearer Token Validation
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            // Bind token validation parameters via IServiceProvider to resolve the key ring
            var serviceProvider = services.BuildServiceProvider();
            var jwtOptions = configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>() ?? new JwtOptions();
            var keyRing = serviceProvider.GetRequiredService<IJwtKeyRing>();

            options.RequireHttpsMetadata = environment.IsProduction();
            options.SaveToken = false; // Do not store raw tokens in HttpContext to avoid memory retention

            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtOptions.Issuer,
                ValidateAudience = true,
                ValidAudience = jwtOptions.Audience,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                ClockSkew = TimeSpan.Zero, // Strict zero clock skew (NTP synchronized hosts)
                ValidAlgorithms = [SecurityAlgorithms.HmacSha256], // Strictly allow only HMAC-SHA256
                IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                {
                    if (string.IsNullOrWhiteSpace(kid))
                    {
                        throw new SecurityTokenException("Missing required 'kid' header in JWT.");
                    }

                    if (keyRing.TryGetKey(kid, out var key) && key != null)
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
                    // Suppress default challenge response if already handled
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

                    await context.Response.WriteAsJsonAsync(problemDetails, options: (System.Text.Json.JsonSerializerOptions?)null, contentType: "application/problem+json", cancellationToken: context.HttpContext.RequestAborted);
                }
            };
        });

        services.AddAuthorization();

        // 4. Rate Limiting Infrastructure
        services.Configure<RateLimitingOptions>(configuration.GetSection(RateLimitingOptions.SectionName));

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

                await context.HttpContext.Response.WriteAsJsonAsync(problemDetails, options: (System.Text.Json.JsonSerializerOptions?)null, contentType: "application/problem+json", cancellationToken: cancellationToken);
            };

            // Policy: Auth.Registration (Default 5 req/min/IP)
            limiterOptions.AddPolicy(AuthRateLimitPolicies.Registration, httpContext =>
            {
                var clientIp = ResolveClientIp(httpContext);
                if (clientIp == null)
                {
                    // Missing client IP: do not grant unrestricted access; assign to restricted 1-permit partition
                    return RateLimitPartition.GetFixedWindowLimiter(
                        "unresolved_ip_registration",
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 1,
                            Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                            QueueLimit = 0
                        });
                }

                return RateLimitPartition.GetSlidingWindowLimiter(
                    $"registration_{clientIp}",
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
                var clientIp = ResolveClientIp(httpContext);
                if (clientIp == null)
                {
                    return RateLimitPartition.GetFixedWindowLimiter(
                        "unresolved_ip_login",
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 1,
                            Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                            QueueLimit = 0
                        });
                }

                return RateLimitPartition.GetSlidingWindowLimiter(
                    $"login_{clientIp}",
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
                var clientIp = ResolveClientIp(httpContext);
                if (clientIp == null)
                {
                    return RateLimitPartition.GetFixedWindowLimiter(
                        "unresolved_ip_refresh",
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 1,
                            Window = TimeSpan.FromSeconds(rateOptions.WindowSeconds),
                            QueueLimit = 0
                        });
                }

                return RateLimitPartition.GetSlidingWindowLimiter(
                    $"refresh_{clientIp}",
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
    /// Configures the HTTP request pipeline with security middleware in strict dependency order:
    /// 1. ForwardedHeaders (processes trusted proxy client IP before all downstream middleware)
    /// 2. RateLimiter (enforces rate limits based on resolved client IP)
    /// 3. Authentication (validates JWT Bearer tokens)
    /// 4. Authorization (enforces security policies)
    /// </summary>
    public static WebApplication UseMaintenXSecurity(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Process forwarded headers first before any IP-dependent or security middleware
        app.UseForwardedHeaders();

        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();

        return app;
    }

    private static IPAddress? ResolveClientIp(HttpContext httpContext)
    {
        return httpContext.Connection.RemoteIpAddress;
    }
}

