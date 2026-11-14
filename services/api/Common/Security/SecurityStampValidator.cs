namespace MaintenX.Api.Common.Security;

using MaintenX.Api.Domain.Auth;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

/// <summary>
/// Scoped service that validates user security stamps using an in-memory cache with a 60-second absolute TTL,
/// falling back to the database abstraction on cache misses. Invalidates cached entries on user credential/stamp updates.
/// </summary>
public sealed class SecurityStampValidator : ISecurityStampValidator
{
    private const string CacheKeyPrefix = "auth:sec-stamp:";
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private readonly IUserSecurityStampStore _stampStore;
    private readonly IMemoryCache _cache;
    private readonly ILogger<SecurityStampValidator> _logger;

    public SecurityStampValidator(
        IUserSecurityStampStore stampStore,
        IMemoryCache cache,
        ILogger<SecurityStampValidator> logger)
    {
        _stampStore = stampStore ?? throw new ArgumentNullException(nameof(stampStore));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<bool> ValidateAsync(Guid userId, string securityStamp, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty || string.IsNullOrWhiteSpace(securityStamp))
        {
            return false;
        }

        var normalizedStamp = securityStamp.Trim();
        var cacheKey = GetCacheKey(userId);

        // 1. Check in-memory cache
        if (_cache.TryGetValue(cacheKey, out SecurityStampCacheEntry? cached) && cached != null)
        {
            return cached.Status == UserStatus.Active &&
                   string.Equals(cached.SecurityStamp, normalizedStamp, StringComparison.Ordinal);
        }

        // 2. Cache miss: Query database through store abstraction
        var userRecord = await _stampStore.GetSecurityStampAsync(userId, cancellationToken);

        if (userRecord == null)
        {
            _logger.LogWarning("Security stamp validation failed: user {UserId} was not found.", userId);
            return false;
        }

        // 3. Populate in-memory cache with strict 60s absolute TTL
        var entry = new SecurityStampCacheEntry(userRecord.SecurityStamp, userRecord.Status);
        _cache.Set(cacheKey, entry, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = CacheTtl
        });

        // 4. Validate credentials and account status
        var isValid = userRecord.Status == UserStatus.Active &&
                      string.Equals(userRecord.SecurityStamp, normalizedStamp, StringComparison.Ordinal);

        if (!isValid)
        {
            _logger.LogWarning("Security stamp validation failed for user {UserId}: stamp mismatch or user status is {Status}.", userId, userRecord.Status);
        }

        return isValid;
    }

    /// <inheritdoc />
    public void Invalidate(Guid userId)
    {
        if (userId != Guid.Empty)
        {
            _cache.Remove(GetCacheKey(userId));
        }
    }

    private static string GetCacheKey(Guid userId) => $"{CacheKeyPrefix}{userId:D}";

    /// <summary>
    /// Internal record representing the cached security state for a user.
    /// </summary>
    internal sealed record SecurityStampCacheEntry(string SecurityStamp, UserStatus Status);
}
