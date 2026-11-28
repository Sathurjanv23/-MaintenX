namespace MaintenX.Api.Application.Authorization.Contracts;

/// <summary>
/// Centralized platform synchronization key for PostgreSQL transaction-scoped advisory locking
/// (<c>pg_advisory_xact_lock(PlatformAuthorizationCoordination.AdvisoryLockId)</c>).
/// Coordinates all platform administrator lifecycle mutations including bootstrap,
/// grant creation, and grant revocation across concurrent server transactions.
/// </summary>
public static class PlatformAuthorizationCoordination
{
    public const long AdvisoryLockId = 748291034L;
}
