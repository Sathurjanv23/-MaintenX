namespace MaintenX.Api.Application.Tenancy.Services;

using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Models;

/// <summary>
/// Application service contract for tenant onboarding, settings management, and lifecycle state operations.
/// </summary>
public interface ITenantService
{
    /// <summary>
    /// Creates and onboards a new tenant organization with an initial Owner membership for the creator user.
    /// Guarantees atomic transaction durability and slug uniqueness.
    /// </summary>
    /// <param name="creatorUserId">Identifier of the authenticated user creating the tenant.</param>
    /// <param name="request">Tenant creation parameters including slug and display name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="CreateTenantResult"/> indicating creation success, slug conflict, or validation error.</returns>
    Task<CreateTenantResult> CreateTenantAsync(
        Guid creatorUserId,
        CreateTenantRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves tenant organization information by unique tenant identifier using request-scoped caller context.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantResult"/> with tenant details or not-found outcome.</returns>
    Task<TenantResult> GetTenantByIdAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves tenant organization information by unique tenant identifier with explicit verified actor context.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant.</param>
    /// <param name="actor">Verified actor context of the caller.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantResult"/> with tenant details or not-found outcome.</returns>
    Task<TenantResult> GetTenantByIdAsync(
        Guid tenantId,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves tenant organization information by normalized URL slug using request-scoped caller context.
    /// </summary>
    /// <param name="slug">URL slug of the target tenant.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantResult"/> with tenant details or not-found outcome.</returns>
    Task<TenantResult> GetTenantBySlugAsync(
        string slug,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves tenant organization information by normalized URL slug with explicit verified actor context.
    /// </summary>
    /// <param name="slug">URL slug of the target tenant.</param>
    /// <param name="actor">Verified actor context of the caller.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantResult"/> with tenant details or not-found outcome.</returns>
    Task<TenantResult> GetTenantBySlugAsync(
        string slug,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates permitted tenant settings (e.g. display name) using request-scoped caller context.
    /// Enforces optimistic concurrency token matching and tenant boundary constraints.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant organization.</param>
    /// <param name="request">Update parameters.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantResult"/> with updated details or validation/concurrency error.</returns>
    Task<TenantResult> UpdateTenantAsync(
        Guid tenantId,
        UpdateTenantRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates permitted tenant settings with explicit verified actor context.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant organization.</param>
    /// <param name="request">Update parameters.</param>
    /// <param name="actor">Verified actor context of the caller.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantResult"/> with updated details or validation/concurrency error.</returns>
    Task<TenantResult> UpdateTenantAsync(
        Guid tenantId,
        UpdateTenantRequest request,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Transitions a tenant organization to Active status using request-scoped caller context.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant organization.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantLifecycleResult"/> representing transition outcome.</returns>
    Task<TenantLifecycleResult> ActivateTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Transitions a tenant organization to Active status with explicit verified actor context.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant organization.</param>
    /// <param name="actor">Verified actor context of the caller.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantLifecycleResult"/> representing transition outcome.</returns>
    Task<TenantLifecycleResult> ActivateTenantAsync(
        Guid tenantId,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Suspends an active tenant organization using request-scoped caller context.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant organization.</param>
    /// <param name="reason">Administrative justification for suspension.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantLifecycleResult"/> representing transition outcome.</returns>
    Task<TenantLifecycleResult> SuspendTenantAsync(
        Guid tenantId,
        string reason,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Suspends an active tenant organization with explicit verified actor context.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant organization.</param>
    /// <param name="reason">Administrative justification for suspension.</param>
    /// <param name="actor">Verified actor context of the caller.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantLifecycleResult"/> representing transition outcome.</returns>
    Task<TenantLifecycleResult> SuspendTenantAsync(
        Guid tenantId,
        string reason,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Permanently deactivates a tenant organization using request-scoped caller context. Terminal state.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant organization.</param>
    /// <param name="reason">Administrative justification for deactivation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantLifecycleResult"/> representing transition outcome.</returns>
    Task<TenantLifecycleResult> DeactivateTenantAsync(
        Guid tenantId,
        string reason,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Permanently deactivates a tenant organization with explicit verified actor context. Terminal state.
    /// </summary>
    /// <param name="tenantId">Identifier of the target tenant organization.</param>
    /// <param name="reason">Administrative justification for deactivation.</param>
    /// <param name="actor">Verified actor context of the caller.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="TenantLifecycleResult"/> representing transition outcome.</returns>
    Task<TenantLifecycleResult> DeactivateTenantAsync(
        Guid tenantId,
        string reason,
        TenantActorContext? actor,
        CancellationToken cancellationToken = default);
}
