namespace MaintenX.Api.Application.Authorization.Services;

using MaintenX.Api.Application.Authorization.Contracts;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Restricted one-shot operational CLI entry point for initial Platform Administrator bootstrap.
/// Never starts the public HTTP server when invoked with <c>--bootstrap-platform-admin</c>.
/// </summary>
public static class PlatformAdminBootstrapCommand
{
    public const string CommandFlag = "--bootstrap-platform-admin";

    public static async Task<int> ExecuteAsync(
        IServiceProvider rootServices,
        string[] args,
        CancellationToken cancellationToken = default)
    {
        if (!TryParseArguments(args, out var request, out var parseError))
        {
            Console.Error.WriteLine($"Bootstrap argument error: {parseError}");
            return 3;
        }

        await using var scope = rootServices.CreateAsyncScope();
        var bootstrapService = scope.ServiceProvider.GetRequiredService<IPlatformAdminBootstrapService>();
        var result = await bootstrapService.BootstrapAsync(request!, cancellationToken);

        Console.WriteLine($"Outcome={result.Outcome} TargetUserId={result.TargetUserId} GrantId={result.GrantId} Message={result.Message}");

        return result.Outcome switch
        {
            PlatformAdminBootstrapOutcome.Created => 0,
            PlatformAdminBootstrapOutcome.AlreadyProvisionedForSameUser => 0,
            PlatformAdminBootstrapOutcome.UnauthorizedOperation => 2,
            PlatformAdminBootstrapOutcome.TargetNotFound => 3,
            PlatformAdminBootstrapOutcome.TargetIneligible => 3,
            PlatformAdminBootstrapOutcome.BootstrapUnavailable => 4,
            _ => 5
        };
    }

    public static bool TryParseArguments(
        string[] args,
        out PlatformAdminBootstrapRequest? request,
        out string? error)
    {
        request = null;
        error = null;

        Guid? targetUserId = null;
        string? targetEmail = null;
        string? reason = null;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (string.Equals(arg, CommandFlag, StringComparison.Ordinal))
            {
                continue;
            }

            if (string.Equals(arg, "--target-user-id", StringComparison.Ordinal))
            {
                if (i + 1 >= args.Length || !Guid.TryParse(args[++i], out var parsed))
                {
                    error = "Invalid or missing GUID value for --target-user-id.";
                    return false;
                }
                targetUserId = parsed;
            }
            else if (string.Equals(arg, "--target-email", StringComparison.Ordinal))
            {
                if (i + 1 >= args.Length)
                {
                    error = "Missing value for --target-email.";
                    return false;
                }
                targetEmail = args[++i];
            }
            else if (string.Equals(arg, "--reason", StringComparison.Ordinal))
            {
                if (i + 1 >= args.Length)
                {
                    error = "Missing value for --reason.";
                    return false;
                }
                reason = args[++i];
            }
            else
            {
                error = $"Unsupported bootstrap argument '{arg}'.";
                return false;
            }
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            error = "--reason is required.";
            return false;
        }

        request = new PlatformAdminBootstrapRequest(targetUserId, targetEmail, reason);
        return true;
    }
}
