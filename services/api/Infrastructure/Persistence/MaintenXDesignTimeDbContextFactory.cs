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
            .AddEnvironmentVariables()
            .Build();

        var connectionString = configuration.GetConnectionString("DefaultConnection")
            ?? "Host=localhost;Port=5432;Database=maintenx_dev;Username=maintenx_app;Password=maintenx_dev_password_change_in_prod;";

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
