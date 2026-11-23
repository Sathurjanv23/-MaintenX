namespace MaintenX.Api.Application.Tenancy.Middleware;

/// <summary>
/// Attribute that marks an endpoint or controller as requiring an active, verified tenant context.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = false, AllowMultiple = false)]
public sealed class RequireTenantContextAttribute : Attribute, IRequireTenantContextMetadata
{
}
