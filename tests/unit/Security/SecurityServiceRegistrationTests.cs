namespace MaintenX.UnitTests.Security;

using System.Security.Cryptography;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Configuration;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using ISecurityStampValidator = MaintenX.Api.Common.Security.ISecurityStampValidator;
using SecurityStampValidator = MaintenX.Api.Common.Security.SecurityStampValidator;

public class SecurityServiceRegistrationTests
{
    private static string GenerateBase64Key(int byteCount = 32)
    {
        var bytes = new byte[byteCount];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }

    private static IServiceCollection CreateConfiguredServices()
    {
        var services = new ServiceCollection();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "https://api.maintenx.internal",
                ["Jwt:Audience"] = "https://maintenx.internal",
                ["Jwt:KeyId"] = "test-key-id-v1",
                ["Jwt:SigningKey"] = GenerateBase64Key(32),
                ["Jwt:AccessTokenLifetimeMinutes"] = "15",
                ["Jwt:RetiredKeyRetentionHours"] = "24",
                ["RateLimiting:RegistrationPermitLimit"] = "5",
                ["RateLimiting:LoginPermitLimit"] = "10",
                ["RateLimiting:RefreshPermitLimit"] = "30",
                ["RateLimiting:WindowSeconds"] = "60",
                ["RateLimiting:SegmentsPerWindow"] = "6",
                ["RateLimiting:MaxTrackedPartitions"] = "1000",
                ["ConnectionStrings:DefaultConnection"] = "Host=localhost;Database=dummy;Username=dummy;Password=dummy"
            })
            .Build();

        var environment = new FakeHostEnvironment("Development");
        services.AddSingleton<IHostEnvironment>(environment);
        services.AddLogging();
        services.AddRouting();
        services.AddWebEncoders();

        // DbContext registration
        services.AddDbContext<MaintenXDbContext>(options =>
        {
            options.UseNpgsql("Host=localhost;Database=dummy;Username=dummy;Password=dummy");
        });

        // Register Security Services
        services.AddMaintenXSecurity(configuration, environment);

        return services;
    }

    [Fact]
    public void AddMaintenXSecurity_RegistersPasswordHasher_AsSingleton()
    {
        var services = CreateConfiguredServices();
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IPasswordHasher<User>));

        Assert.NotNull(descriptor);
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        Assert.Equal(typeof(PasswordHasher<User>), descriptor.ImplementationType);
    }

    [Fact]
    public void AddMaintenXSecurity_RegistersPasswordSecurityService_AsSingleton()
    {
        var services = CreateConfiguredServices();
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IPasswordSecurityService));

        Assert.NotNull(descriptor);
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        Assert.Equal(typeof(PasswordSecurityService), descriptor.ImplementationType);
    }

    [Fact]
    public void AddMaintenXSecurity_RegistersJwtTokenService_AsSingleton()
    {
        var services = CreateConfiguredServices();
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IJwtTokenService));

        Assert.NotNull(descriptor);
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        Assert.Equal(typeof(JwtTokenService), descriptor.ImplementationType);
    }

    [Fact]
    public void AddMaintenXSecurity_RegistersRefreshTokenService_AsSingleton()
    {
        var services = CreateConfiguredServices();
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IRefreshTokenService));

        Assert.NotNull(descriptor);
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        Assert.Equal(typeof(RefreshTokenService), descriptor.ImplementationType);
    }

    [Fact]
    public void AddMaintenXSecurity_RegistersUserSecurityStampStore_AsScoped()
    {
        var services = CreateConfiguredServices();
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IUserSecurityStampStore));

        Assert.NotNull(descriptor);
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
        Assert.Equal(typeof(EfUserSecurityStampStore), descriptor.ImplementationType);
    }

    [Fact]
    public void AddMaintenXSecurity_RegistersSecurityStampValidator_AsScoped()
    {
        var services = CreateConfiguredServices();
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(ISecurityStampValidator));

        Assert.NotNull(descriptor);
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
        Assert.Equal(typeof(SecurityStampValidator), descriptor.ImplementationType);
    }

    [Fact]
    public void AddMaintenXSecurity_RegistersMemoryCache()
    {
        var services = CreateConfiguredServices();
        var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IMemoryCache));

        Assert.NotNull(descriptor);
    }

    [Fact]
    public void AllSecurityServices_CanBeResolvedFromServiceProvider()
    {
        var services = CreateConfiguredServices();
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });

        // Singletons resolved from root
        var passwordHasher = provider.GetRequiredService<IPasswordHasher<User>>();
        var passwordSecurityService = provider.GetRequiredService<IPasswordSecurityService>();
        var jwtTokenService = provider.GetRequiredService<IJwtTokenService>();
        var refreshTokenService = provider.GetRequiredService<IRefreshTokenService>();
        var memoryCache = provider.GetRequiredService<IMemoryCache>();

        Assert.NotNull(passwordHasher);
        Assert.NotNull(passwordSecurityService);
        Assert.NotNull(jwtTokenService);
        Assert.NotNull(refreshTokenService);
        Assert.NotNull(memoryCache);

        // Scoped services resolved in scope
        using var scope = provider.CreateScope();
        var stampStore = scope.ServiceProvider.GetRequiredService<IUserSecurityStampStore>();
        var stampValidator = scope.ServiceProvider.GetRequiredService<ISecurityStampValidator>();

        Assert.NotNull(stampStore);
        Assert.NotNull(stampValidator);
    }

    private sealed class FakeHostEnvironment : IHostEnvironment
    {
        public FakeHostEnvironment(string environmentName)
        {
            EnvironmentName = environmentName;
        }

        public string EnvironmentName { get; set; }
        public string ApplicationName { get; set; } = "MaintenX.Test";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
