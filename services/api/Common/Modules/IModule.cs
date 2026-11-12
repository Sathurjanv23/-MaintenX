namespace MaintenX.Api.Common.Modules;

/// <summary>
/// Defines the contract for modular monolith domain modules.
/// Each feature module (e.g., Tenancy, Assets, WorkOrders) implements this contract
/// to register its dependencies and map its endpoints independently.
/// </summary>
public interface IModule
{
    /// <summary>
    /// Registers the module's domain services, repositories, and dependencies.
    /// </summary>
    IServiceCollection RegisterModule(IServiceCollection services, IConfiguration configuration);

    /// <summary>
    /// Maps the module's API endpoints onto the application endpoint router.
    /// </summary>
    IEndpointRouteBuilder MapEndpoints(IEndpointRouteBuilder endpoints);
}

