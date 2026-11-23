namespace MaintenX.Api.Application.Tenancy.Context;

/// <summary>
/// Scoped implementation of <see cref="ITenantContextAccessor"/>.
/// Enforces request-level isolation and protects against post-resolution mutations.
/// </summary>
public sealed class TenantContextAccessor : ITenantContextAccessor
{
    private ITenantContext? _current;

    /// <inheritdoc />
    public ITenantContext? Current => _current;

    /// <inheritdoc />
    public bool HasContext => _current != null;

    /// <summary>
    /// Sets the verified tenant context for the current request scope.
    /// Can only be called once per request scope to prevent cross-tenant context mutation.
    /// </summary>
    /// <param name="context">The verified tenant context.</param>
    /// <exception cref="ArgumentNullException">Thrown if context is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown if tenant context is already initialized in this scope.</exception>
    public void SetContext(ITenantContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (_current is not null)
        {
            throw new InvalidOperationException(
                $"Tenant context has already been initialized for tenant '{_current.TenantId}' and cannot be mutated.");
        }

        _current = context;
    }
}
