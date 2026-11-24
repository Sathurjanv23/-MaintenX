namespace MaintenX.Api.Application.Tenancy.Resolution;

using System.Security.Claims;
using MaintenX.Api.Application.Tenancy.Models;

/// <summary>
/// Result outcome for server-side trusted actor resolution from an authenticated HTTP request.
/// </summary>
public sealed class TenantActorResolutionResult
{
    public bool IsSuccess { get; }
    public TenantActorContext? Actor { get; }
    public int StatusCode { get; }
    public string? ErrorTitle { get; }
    public string? ErrorDetail { get; }

    private TenantActorResolutionResult(bool isSuccess, TenantActorContext? actor, int statusCode, string? errorTitle, string? errorDetail)
    {
        IsSuccess = isSuccess;
        Actor = actor;
        StatusCode = statusCode;
        ErrorTitle = errorTitle;
        ErrorDetail = errorDetail;
    }

    public static TenantActorResolutionResult Success(TenantActorContext actor)
    {
        ArgumentNullException.ThrowIfNull(actor);
        return new TenantActorResolutionResult(true, actor, 200, null, null);
    }

    public static TenantActorResolutionResult Failure(int statusCode, string title, string detail)
    {
        return new TenantActorResolutionResult(false, null, statusCode, title, detail);
    }
}

/// <summary>
/// Service responsible for resolving server-side verified, trusted <see cref="TenantActorContext"/>
/// from an authenticated caller's <see cref="ClaimsPrincipal"/> and active verified tenant context.
/// Enforces identity validity, session non-revocation, security stamp consistency, and denial by default.
/// Strictly prevents client-forged actor identities or platform administrator privilege escalation.
/// </summary>
public interface ITenantActorResolver
{
    /// <summary>
    /// Resolves a trusted, authenticated actor context for tenant operations.
    /// Supports both tenant-neutral operations (e.g. onboarding, discovering own memberships)
    /// and tenant-scoped operations where an active <see cref="MaintenX.Api.Application.Tenancy.Context.ITenantContext"/> is established.
    /// </summary>
    /// <param name="user">The claims principal representing the caller.</param>
    /// <param name="requireActiveTenantContext">
    /// If true, requires the caller to have established a verified, active tenant context for the request.
    /// If false, allows tenant-neutral authenticated operations (e.g. onboarding or global membership discovery).
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantActorResolutionResult"/> with the verified actor or explicit failure details.</returns>
    Task<TenantActorResolutionResult> ResolveActorAsync(
        ClaimsPrincipal? user,
        bool requireActiveTenantContext = false,
        CancellationToken cancellationToken = default);
}
