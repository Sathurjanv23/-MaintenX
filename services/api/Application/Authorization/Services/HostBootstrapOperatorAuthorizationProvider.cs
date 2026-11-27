namespace MaintenX.Api.Application.Authorization.Services;

using MaintenX.Api.Application.Authorization.Contracts;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Default host-environment operator authorization provider.
/// Requires explicit server-side operational opt-in (<c>MaintenX:Bootstrap:AllowExecution == "true"</c>)
/// and derives operator identity from the OS/host process identity (<c>os:&lt;user&gt;@&lt;machine&gt;</c>).
/// </summary>
public sealed class HostBootstrapOperatorAuthorizationProvider : IBootstrapOperatorAuthorizationProvider
{
    public const string AllowExecutionConfigKey = "MaintenX:Bootstrap:AllowExecution";
    private readonly IConfiguration _configuration;

    public HostBootstrapOperatorAuthorizationProvider(IConfiguration configuration)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public Task<BootstrapOperatorAuthorizationResult> AuthorizeAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var allowExecution = _configuration[AllowExecutionConfigKey];
        if (!string.Equals(allowExecution, "true", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(BootstrapOperatorAuthorizationResult.Denied(
                "Operational bootstrap execution is disabled in the current environment."));
        }

        var osUser = Environment.UserName?.Trim();
        var machine = Environment.MachineName?.Trim();
        if (string.IsNullOrWhiteSpace(osUser) || string.IsNullOrWhiteSpace(machine))
        {
            return Task.FromResult(BootstrapOperatorAuthorizationResult.Denied(
                "Unable to determine verified OS operator execution identity."));
        }

        var operatorIdentity = $"os:{osUser}@{machine}";
        if (operatorIdentity.Length > 200)
        {
            operatorIdentity = operatorIdentity[..200];
        }

        return Task.FromResult(BootstrapOperatorAuthorizationResult.Authorized(operatorIdentity));
    }
}
