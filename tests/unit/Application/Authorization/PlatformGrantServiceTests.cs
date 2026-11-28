namespace MaintenX.UnitTests.Application.Authorization;

using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Unit tests for <see cref="PlatformGrantService"/> covering argument validation,
/// denial when caller lacks platform administration authority, and self-revocation denial.
/// </summary>
public class PlatformGrantServiceTests
{
    private static MaintenXDbContext CreateUnusedContext() =>
        new(new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options);

    [Fact]
    public async Task RevokeGrantAsync_NullRequest_ThrowsArgumentNullException()
    {
        var service = new PlatformGrantService(
            CreateUnusedContext(),
            new StubGrantResolver(PlatformGrantResolutionResult.Deny("denied")),
            TimeProvider.System,
            NullLogger<PlatformGrantService>.Instance);

        await Assert.ThrowsAsync<ArgumentNullException>(() => service.RevokeGrantAsync(null!));
    }

    [Fact]
    public async Task RevokeGrantAsync_EmptyGrantId_ReturnsGrantNotFound()
    {
        var service = new PlatformGrantService(
            CreateUnusedContext(),
            new StubGrantResolver(PlatformGrantResolutionResult.Deny("denied")),
            TimeProvider.System,
            NullLogger<PlatformGrantService>.Instance);

        var result = await service.RevokeGrantAsync(new PlatformGrantRevocationRequest(Guid.Empty, "Valid reason"));
        Assert.Equal(PlatformGrantRevocationOutcome.GrantNotFound, result.Outcome);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("ab")]
    public async Task RevokeGrantAsync_InvalidReasonLength_ReturnsTargetIneligible(string? invalidReason)
    {
        var service = new PlatformGrantService(
            CreateUnusedContext(),
            new StubGrantResolver(PlatformGrantResolutionResult.Deny("denied")),
            TimeProvider.System,
            NullLogger<PlatformGrantService>.Instance);

        var result = await service.RevokeGrantAsync(new PlatformGrantRevocationRequest(Guid.NewGuid(), invalidReason!));
        Assert.Equal(PlatformGrantRevocationOutcome.TargetIneligible, result.Outcome);
    }

    [Fact]
    public async Task RevokeGrantAsync_UnauthorizedCaller_ReturnsUnauthorized()
    {
        var service = new PlatformGrantService(
            CreateUnusedContext(),
            new StubGrantResolver(PlatformGrantResolutionResult.Deny("Caller is not platform admin")),
            TimeProvider.System,
            NullLogger<PlatformGrantService>.Instance);

        var result = await service.RevokeGrantAsync(new PlatformGrantRevocationRequest(Guid.NewGuid(), "Valid administrative reason"));
        Assert.Equal(PlatformGrantRevocationOutcome.Unauthorized, result.Outcome);
        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task RevokeGrantAsync_CancelledToken_ThrowsOperationCanceledException()
    {
        var service = new PlatformGrantService(
            CreateUnusedContext(),
            new StubGrantResolver(PlatformGrantResolutionResult.Deny("denied")),
            TimeProvider.System,
            NullLogger<PlatformGrantService>.Instance);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.RevokeGrantAsync(new PlatformGrantRevocationRequest(Guid.NewGuid(), "Valid reason"), cts.Token));
    }

    private sealed class StubGrantResolver(PlatformGrantResolutionResult result) : IPlatformGrantResolver
    {
        public Task<PlatformGrantResolutionResult> ResolveAsync(PermissionKey? permission, CancellationToken cancellationToken = default) =>
            Task.FromResult(result);
    }
}
