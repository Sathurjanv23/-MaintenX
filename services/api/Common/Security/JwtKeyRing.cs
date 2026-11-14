namespace MaintenX.Api.Common.Security;

using System.Collections.Concurrent;
using MaintenX.Api.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Thread-safe implementation of <see cref="IJwtKeyRing"/>.
/// Manages active key issuance and enforces a mandatory 24-hour retention lifecycle for retired verification keys.
/// Evaluates elapsed retention dynamically using an injectable <see cref="TimeProvider"/>.
/// </summary>
public sealed class JwtKeyRing : IJwtKeyRing
{
    private readonly string _activeKeyId;
    private readonly SymmetricSecurityKey _activeSigningKey;
    private readonly SigningCredentials _signingCredentials;
    private readonly int _retentionHours;
    private readonly TimeProvider _timeProvider;

    private readonly ConcurrentDictionary<string, RetiredKeyEntry> _retiredKeys = new(StringComparer.Ordinal);

    public string ActiveKeyId => _activeKeyId;

    public SecurityKey ActiveSigningKey => _activeSigningKey;

    public JwtKeyRing(IOptions<JwtOptions> options, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var jwtOptions = options.Value;

        if (string.IsNullOrWhiteSpace(jwtOptions.KeyId))
        {
            throw new InvalidOperationException("Active Key ID cannot be null or empty.");
        }

        if (string.IsNullOrWhiteSpace(jwtOptions.SigningKey))
        {
            throw new InvalidOperationException("Active Signing Key cannot be null or empty.");
        }

        _timeProvider = timeProvider ?? TimeProvider.System;
        _retentionHours = jwtOptions.RetiredKeyRetentionHours > 0 ? jwtOptions.RetiredKeyRetentionHours : 24;

        _activeKeyId = jwtOptions.KeyId.Trim();
        var primaryBytes = Convert.FromBase64String(jwtOptions.SigningKey.Trim());
        _activeSigningKey = new SymmetricSecurityKey(primaryBytes)
        {
            KeyId = _activeKeyId
        };

        _signingCredentials = new SigningCredentials(_activeSigningKey, SecurityAlgorithms.HmacSha256);

        if (jwtOptions.VerificationKeys is { Count: > 0 })
        {
            foreach (var (kid, base64Material) in jwtOptions.VerificationKeys)
            {
                if (string.IsNullOrWhiteSpace(kid) || string.IsNullOrWhiteSpace(base64Material))
                {
                    continue;
                }

                var trimmedKid = kid.Trim();
                if (string.Equals(trimmedKid, _activeKeyId, StringComparison.Ordinal))
                {
                    continue;
                }

                var retiredAt = jwtOptions.RetiredAtTimestamps.TryGetValue(trimmedKid, out var ts)
                    ? ts
                    : _timeProvider.GetUtcNow();

                RetireKey(trimmedKid, base64Material.Trim(), retiredAt);
            }
        }
    }

    public SigningCredentials CreateSigningCredentials() => _signingCredentials;

    public bool TryGetKey(string? kid, out SecurityKey? key)
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            key = null;
            return false;
        }

        var trimmedKid = kid.Trim();

        // 1. Check primary active signing key
        if (string.Equals(trimmedKid, _activeKeyId, StringComparison.Ordinal))
        {
            key = _activeSigningKey;
            return true;
        }

        // 2. Check retired verification key ring
        if (_retiredKeys.TryGetValue(trimmedKid, out var entry))
        {
            var retentionWindow = TimeSpan.FromHours(_retentionHours);
            var now = _timeProvider.GetUtcNow();

            // Enforce retention window: key is valid only while now < RetiredAtUtc + RetentionWindow
            if (now < entry.RetiredAtUtc + retentionWindow)
            {
                key = entry.SecurityKey;
                return true;
            }

            // Retention period has expired; key is no longer valid for signature verification
            key = null;
            return false;
        }

        key = null;
        return false;
    }

    public IEnumerable<SecurityKey> GetAllKeys()
    {
        var keys = new List<SecurityKey> { _activeSigningKey };
        var retentionWindow = TimeSpan.FromHours(_retentionHours);
        var now = _timeProvider.GetUtcNow();

        foreach (var entry in _retiredKeys.Values)
        {
            if (now < entry.RetiredAtUtc + retentionWindow)
            {
                keys.Add(entry.SecurityKey);
            }
        }

        return keys;
    }

    public void RetireKey(string kid, string keyMaterialBase64, DateTimeOffset? retiredAtUtc = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(kid);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyMaterialBase64);

        var trimmedKid = kid.Trim();
        if (string.Equals(trimmedKid, _activeKeyId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Cannot retire active Key ID '{kid}'. Promote a new active key before retiring.");
        }

        var retiredBytes = Convert.FromBase64String(keyMaterialBase64.Trim());
        var securityKey = new SymmetricSecurityKey(retiredBytes)
        {
            KeyId = trimmedKid
        };

        var timestamp = retiredAtUtc ?? _timeProvider.GetUtcNow();
        _retiredKeys[trimmedKid] = new RetiredKeyEntry(trimmedKid, securityKey, timestamp);
    }

    public bool CanPurgeKey(string kid, out TimeSpan remainingRetention)
    {
        if (string.IsNullOrWhiteSpace(kid) || !_retiredKeys.TryGetValue(kid.Trim(), out var entry))
        {
            remainingRetention = TimeSpan.Zero;
            return false;
        }

        var retentionWindow = TimeSpan.FromHours(_retentionHours);
        var elapsed = _timeProvider.GetUtcNow() - entry.RetiredAtUtc;

        if (elapsed < retentionWindow)
        {
            remainingRetention = retentionWindow - elapsed;
            return false;
        }

        remainingRetention = TimeSpan.Zero;
        return true;
    }

    public bool TryPurgeRetiredKey(string kid, out string? failureReason)
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            failureReason = "Key ID cannot be null or empty.";
            return false;
        }

        var trimmedKid = kid.Trim();
        if (string.Equals(trimmedKid, _activeKeyId, StringComparison.Ordinal))
        {
            failureReason = "Cannot purge the active signing key.";
            return false;
        }

        if (!_retiredKeys.TryGetValue(trimmedKid, out var entry))
        {
            failureReason = $"Retired key '{kid}' was not found in key ring.";
            return false;
        }

        var retentionWindow = TimeSpan.FromHours(_retentionHours);
        var elapsed = _timeProvider.GetUtcNow() - entry.RetiredAtUtc;

        if (elapsed < retentionWindow)
        {
            var remaining = retentionWindow - elapsed;
            failureReason = $"Cannot purge retired key '{kid}': mandatory {_retentionHours}-hour retention period has not elapsed ({remaining.TotalHours:F1}h remaining).";
            return false;
        }

        _retiredKeys.TryRemove(trimmedKid, out _);
        failureReason = null;
        return true;
    }

    public IReadOnlyCollection<RetiredKeyInfo> GetRetiredKeys()
    {
        var retentionWindow = TimeSpan.FromHours(_retentionHours);
        var now = _timeProvider.GetUtcNow();

        return _retiredKeys.Values.Select(entry => new RetiredKeyInfo(
            entry.KeyId,
            entry.RetiredAtUtc,
            entry.RetiredAtUtc + retentionWindow,
            IsExpired: now >= entry.RetiredAtUtc + retentionWindow
        )).ToList();
    }

    private sealed record RetiredKeyEntry(
        string KeyId,
        SymmetricSecurityKey SecurityKey,
        DateTimeOffset RetiredAtUtc);
}
