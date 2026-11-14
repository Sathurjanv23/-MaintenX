namespace MaintenX.Api.Infrastructure.Persistence;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Design-time factory enabling dotnet-ef migrations tooling to instantiate MaintenXDbContext
/// outside of the running application host.
/// </summary>
public sealed class MaintenXDesignTimeDbContextFactory : IDesignTimeDbContextFactory<MaintenXDbContext>
{
    public MaintenXDbContext CreateDbContext(string[] args)
    {
        var basePath = Directory.GetCurrentDirectory();

        var configuration = new ConfigurationBuilder()
            .SetBasePath(basePath)
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddUserSecrets<MaintenXDesignTimeDbContextFactory>(optional: true)
            .AddEnvironmentVariables()
            .Build();

        var connectionString = configuration.GetConnectionString("DefaultConnection");

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Design-time connection string 'DefaultConnection' was not found in configuration or environment variables. " +
                "Please configure 'ConnectionStrings:DefaultConnection' via .NET User Secrets or set 'ConnectionStrings__DefaultConnection'.");
        }

        var optionsBuilder = new DbContextOptionsBuilder<MaintenXDbContext>();
        optionsBuilder.UseNpgsql(connectionString, npgsqlOptions =>
        {
            npgsqlOptions.MigrationsHistoryTable("__EFMigrationsHistory", MaintenXDbContext.DefaultSchema);
            npgsqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(10),
                errorCodesToAdd: null);
            npgsqlOptions.CommandTimeout(30);
        });

        return new MaintenXDbContext(optionsBuilder.Options);
    }
}
