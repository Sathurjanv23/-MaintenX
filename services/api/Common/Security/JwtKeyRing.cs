namespace MaintenX.Api.Common.Security;

using System.Collections.Concurrent;
using MaintenX.Api.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Thread-safe implementation of <see cref="IJwtKeyRing"/>.
/// Decodes Base64 symmetric keys once on initialization and provides fast lookups by 'kid'.
/// </summary>
public sealed class JwtKeyRing : IJwtKeyRing
{
    private readonly string _activeKeyId;
    private readonly SymmetricSecurityKey _activeSigningKey;
    private readonly SigningCredentials _signingCredentials;
    private readonly Dictionary<string, SecurityKey> _allKeys;

    public string ActiveKeyId => _activeKeyId;

    public SecurityKey ActiveSigningKey => _activeSigningKey;

    public JwtKeyRing(IOptions<JwtOptions> options)
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

        _activeKeyId = jwtOptions.KeyId.Trim();
        var primaryBytes = Convert.FromBase64String(jwtOptions.SigningKey.Trim());
        _activeSigningKey = new SymmetricSecurityKey(primaryBytes)
        {
            KeyId = _activeKeyId
        };

        _signingCredentials = new SigningCredentials(_activeSigningKey, SecurityAlgorithms.HmacSha256);

        _allKeys = new Dictionary<string, SecurityKey>(StringComparer.Ordinal)
        {
            [_activeKeyId] = _activeSigningKey
        };

        if (jwtOptions.VerificationKeys is { Count: > 0 })
        {
            foreach (var (kid, base64Material) in jwtOptions.VerificationKeys)
            {
                if (string.IsNullOrWhiteSpace(kid) || string.IsNullOrWhiteSpace(base64Material))
                {
                    continue;
                }

                var trimmedKid = kid.Trim();
                if (!_allKeys.ContainsKey(trimmedKid))
                {
                    var retiredBytes = Convert.FromBase64String(base64Material.Trim());
                    _allKeys[trimmedKid] = new SymmetricSecurityKey(retiredBytes)
                    {
                        KeyId = trimmedKid
                    };
                }
            }
        }
    }

    public SigningCredentials CreateSigningCredentials() => _signingCredentials;

    public bool TryGetKey(string? kid, out SecurityKey? key)
    {
        if (!string.IsNullOrWhiteSpace(kid) && _allKeys.TryGetValue(kid.Trim(), out key))
        {
            return true;
        }

        key = null;
        return false;
    }

    public IEnumerable<SecurityKey> GetAllKeys() => _allKeys.Values;
}

