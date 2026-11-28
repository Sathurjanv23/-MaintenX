namespace MaintenX.UnitTests.Application.Authorization;

using MaintenX.Api.Application.Authorization;
using MaintenX.Api.Application.Authorization.Contracts;
using MaintenX.Api.Application.Authorization.Services;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Unit tests for <see cref="PlatformAdminBootstrapService"/>, <see cref="HostBootstrapOperatorAuthorizationProvider"/>,
/// <see cref="PlatformAdminBootstrapCommand"/>, and <see cref="PlatformRoleGrant.CreateForBootstrap"/>.
/// </summary>
public class PlatformAdminBootstrapServiceTests
{
    private static MaintenXDbContext CreateUnusedContext() =>
        new(new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=unused;Username=unused;Password=unused")
            .Options);

    private static HostBootstrapOperatorAuthorizationProvider CreateProvider(bool allow)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [HostBootstrapOperatorAuthorizationProvider.AllowExecutionConfigKey] = allow ? "true" : "false"
            })
            .Build();
        return new HostBootstrapOperatorAuthorizationProvider(config);
    }

    [Fact]
    public async Task HostOperatorProvider_DeniesByDefault_AndAllowsOnlyWhenExplicitlyEnabled()
    {
        var disabledConfig = new ConfigurationBuilder().Build();
        var disabledProvider = new HostBootstrapOperatorAuthorizationProvider(disabledConfig);
        var denied = await disabledProvider.AuthorizeAsync();
        Assert.False(denied.IsAuthorized);
        Assert.Null(denied.OperatorIdentity);

        var enabledProvider = CreateProvider(allow: true);
        var allowed = await enabledProvider.AuthorizeAsync();
        Assert.True(allowed.IsAuthorized);
        Assert.StartsWith("os:", allowed.OperatorIdentity);
    }

    [Fact]
    public async Task BootstrapAsync_UnauthorizedOperator_ReturnsUnauthorizedOperation()
    {
        var service = new PlatformAdminBootstrapService(
            CreateUnusedContext(),
            CreateProvider(allow: false),
            TimeProvider.System,
            NullLogger<PlatformAdminBootstrapService>.Instance);

        var result = await service.BootstrapAsync(
            new PlatformAdminBootstrapRequest(Guid.NewGuid(), null, "Initial platform setup"));

        Assert.Equal(PlatformAdminBootstrapOutcome.UnauthorizedOperation, result.Outcome);
        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task BootstrapAsync_InvalidTargetOrReason_ReturnsTargetIneligible()
    {
        var service = new PlatformAdminBootstrapService(
            CreateUnusedContext(),
            CreateProvider(allow: true),
            TimeProvider.System,
            NullLogger<PlatformAdminBootstrapService>.Instance);

        Assert.Equal(PlatformAdminBootstrapOutcome.TargetIneligible,
            (await service.BootstrapAsync(new PlatformAdminBootstrapRequest(Guid.Empty, null, "Valid reason"))).Outcome);

        Assert.Equal(PlatformAdminBootstrapOutcome.TargetIneligible,
            (await service.BootstrapAsync(new PlatformAdminBootstrapRequest(null, null, "Valid reason"))).Outcome);

        Assert.Equal(PlatformAdminBootstrapOutcome.TargetIneligible,
            (await service.BootstrapAsync(new PlatformAdminBootstrapRequest(Guid.NewGuid(), "a@b.com", "Valid reason"))).Outcome);

        Assert.Equal(PlatformAdminBootstrapOutcome.TargetIneligible,
            (await service.BootstrapAsync(new PlatformAdminBootstrapRequest(Guid.NewGuid(), null, "ab"))).Outcome);
    }

    [Fact]
    public async Task BootstrapAsync_PreCancelledToken_ThrowsOperationCanceledException()
    {
        var service = new PlatformAdminBootstrapService(
            CreateUnusedContext(),
            CreateProvider(allow: true),
            TimeProvider.System,
            NullLogger<PlatformAdminBootstrapService>.Instance);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.BootstrapAsync(new PlatformAdminBootstrapRequest(Guid.NewGuid(), null, "Valid reason"), cts.Token));
    }

    [Fact]
    public void CreateForBootstrap_DistinguishesDeploymentOperatorFromUserActor()
    {
        var userId = Guid.NewGuid();
        var now = DateTime.UtcNow;

        var bootstrapGrant = PlatformRoleGrant.CreateForBootstrap(userId, PlatformRole.PlatformAdministrator, "os:deploy@prod-01", now);
        Assert.Equal(GrantActorKind.DeploymentOperator, bootstrapGrant.GrantedByActorKind);
        Assert.Null(bootstrapGrant.GrantedByUserId);
        Assert.Equal("os:deploy@prod-01", bootstrapGrant.GrantedByOperatorId);

        var userGrant = PlatformRoleGrant.Create(userId, PlatformRole.PlatformAdministrator, Guid.NewGuid(), now);
        Assert.Equal(GrantActorKind.User, userGrant.GrantedByActorKind);
        Assert.NotNull(userGrant.GrantedByUserId);
        Assert.Null(userGrant.GrantedByOperatorId);

        Assert.Throws<ArgumentException>(() =>
            PlatformRoleGrant.CreateForBootstrap(userId, PlatformRole.PlatformAdministrator, "   ", now));
    }

    [Fact]
    public void BootstrapCommand_RejectsUnsupportedArgumentsAndMissingReason()
    {
        Assert.False(PlatformAdminBootstrapCommand.TryParseArguments(
            new[] { "--bootstrap-platform-admin", "--target-email", "a@b.com", "--authorized=true", "--reason", "init" },
            out _,
            out _));

        Assert.False(PlatformAdminBootstrapCommand.TryParseArguments(
            new[] { "--bootstrap-platform-admin", "--target-user-id", Guid.NewGuid().ToString() },
            out _,
            out _));

        Assert.True(PlatformAdminBootstrapCommand.TryParseArguments(
            new[] { "--bootstrap-platform-admin", "--target-user-id", Guid.NewGuid().ToString(), "--reason", "Initial setup" },
            out var req,
            out var err));
        Assert.Null(err);
        Assert.NotNull(req);
    }

    [Fact]
    public void AddMaintenXAuthorization_RegistersBootstrapServicesScoped()
    {
        var services = new ServiceCollection();
        services.AddMaintenXAuthorization();

        Assert.Equal(ServiceLifetime.Scoped,
            Assert.Single(services, d => d.ServiceType == typeof(IBootstrapOperatorAuthorizationProvider)).Lifetime);
        Assert.Equal(ServiceLifetime.Scoped,
            Assert.Single(services, d => d.ServiceType == typeof(IPlatformAdminBootstrapService)).Lifetime);
    }

    [Fact]
    public void SecurityAuditMetadata_ForBootstrap_ProducesCorrelatedImmutableMetadata()
    {
        var grantId = Guid.NewGuid();
        var meta = SecurityAuditMetadata.ForBootstrap(grantId);

        Assert.Equal(SecurityAuditMetadata.Reasons.PlatformAdministratorBootstrap, meta.Reason);
        Assert.Equal($"grant_{grantId:N}", meta.DetectedLineage);
        Assert.Equal(SecurityAuditMetadata.Actions.PlatformAdministratorGranted, meta.ActionTaken);

        Assert.Throws<ArgumentException>(() => SecurityAuditMetadata.ForBootstrap(Guid.Empty));
    }
}
