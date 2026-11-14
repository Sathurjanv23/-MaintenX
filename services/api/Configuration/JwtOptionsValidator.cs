namespace MaintenX.Api.Configuration;

using Microsoft.Extensions.Options;

/// <summary>
/// Fail-fast validator for <see cref="JwtOptions"/>.
/// Ensures all security baselines, minimum key entropy (&gt;= 256 bits),
/// valid Base64 encodings, and required claims are validated on application startup.
/// </summary>
public sealed class JwtOptionsValidator : IValidateOptions<JwtOptions>
{
    public const int MinimumKeyLengthBytes = 32; // 256 bits
    public const int MandatoryRetiredKeyRetentionHours = 24;

    public ValidateOptionsResult Validate(string? name, JwtOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            failures.Add("Missing required JWT configuration: 'Jwt:Issuer'.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            failures.Add("Missing required JWT configuration: 'Jwt:Audience'.");
        }

        if (string.IsNullOrWhiteSpace(options.KeyId))
        {
            failures.Add("Missing required JWT configuration: 'Jwt:KeyId'. Every active signing key requires an explicit 'kid'.");
        }

        if (options.AccessTokenLifetimeMinutes <= 0)
        {
            failures.Add($"Invalid JWT access token lifetime: {options.AccessTokenLifetimeMinutes} minutes. Lifetime must be greater than zero.");
        }

        if (options.RetiredKeyRetentionHours != MandatoryRetiredKeyRetentionHours)
        {
            failures.Add($"Invalid JWT retired key retention hours: {options.RetiredKeyRetentionHours}. The security architecture strictly mandates a retention period of exactly {MandatoryRetiredKeyRetentionHours} hours.");
        }

        if (string.IsNullOrWhiteSpace(options.SigningKey))
        {
            failures.Add("Missing required JWT signing key: 'Jwt:SigningKey'. A Base64-encoded key of at least 256 bits (32 bytes) is required.");
        }
        else
        {
            try
            {
                var decodedKey = Convert.FromBase64String(options.SigningKey.Trim());
                if (decodedKey.Length < MinimumKeyLengthBytes)
                {
                    failures.Add($"Insufficient key entropy in 'Jwt:SigningKey'. Decoded key length is {decodedKey.Length * 8} bits ({decodedKey.Length} bytes). Minimum required is {MinimumKeyLengthBytes * 8} bits ({MinimumKeyLengthBytes} bytes).");
                }
            }
            catch (FormatException)
            {
                failures.Add("Invalid 'Jwt:SigningKey'. The signing key must be a valid Base64-encoded string.");
            }
        }

        if (options.VerificationKeys is { Count: > 0 })
        {
            foreach (var (keyId, base64Key) in options.VerificationKeys)
            {
                if (string.IsNullOrWhiteSpace(keyId))
                {
                    failures.Add("Verification key ring contains an invalid empty or whitespace key ID.");
                    continue;
                }

                if (string.IsNullOrWhiteSpace(base64Key))
                {
                    failures.Add($"Verification key '{keyId}' has missing or empty key material.");
                    continue;
                }

                try
                {
                    var decoded = Convert.FromBase64String(base64Key.Trim());
                    if (decoded.Length < MinimumKeyLengthBytes)
                    {
                        failures.Add($"Verification key '{keyId}' has insufficient entropy: {decoded.Length * 8} bits ({decoded.Length} bytes). Minimum required is {MinimumKeyLengthBytes * 8} bits ({MinimumKeyLengthBytes} bytes).");
                    }
                }
                catch (FormatException)
                {
                    failures.Add($"Verification key '{keyId}' is not a valid Base64-encoded string.");
                }

                // If the active key ID is also in the verification ring, its material must match
                if (string.Equals(keyId, options.KeyId, StringComparison.Ordinal) &&
                    !string.Equals(base64Key.Trim(), options.SigningKey?.Trim(), StringComparison.Ordinal))
                {
                    failures.Add($"Verification key ring contains active KeyId '{keyId}' with conflicting key material.");
                }
            }
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}

