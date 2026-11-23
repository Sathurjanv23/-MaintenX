namespace MaintenX.UnitTests.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Services;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Unit tests for TenantService verifying input validation, authorization guards,
/// error handling, and safe responses.
/// </summary>
public class TenantServiceUnitTests
{
    private static MaintenXDbContext CreateDummyContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=dummy;Username=dummy;Password=dummy")
            .Options;

        return new MaintenXDbContext(options);
    }

    [Fact]
    public async Task CreateTenantAsync_NullRequest_ReturnsValidationFailed()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        var result = await service.CreateTenantAsync(Guid.NewGuid(), null!);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("VALIDATION_FAILED", result.ErrorCode);
        Assert.Contains("null", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateTenantAsync_EmptyCreatorUserId_ReturnsUnauthorized()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var request = new CreateTenantRequest("acme", "Acme Corporation");

        var result = await service.CreateTenantAsync(Guid.Empty, request);

        Assert.False(result.IsSuccess);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("UNAUTHORIZED", result.ErrorCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("a")]
    [InlineData("acme--corp")]
    [InlineData("acme_corp")]
    [InlineData("acme corp")]
    public async Task CreateTenantAsync_InvalidSlug_ReturnsValidationFailed(string invalidSlug)
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var request = new CreateTenantRequest(invalidSlug, "Acme Corporation");

        var result = await service.CreateTenantAsync(Guid.NewGuid(), request);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("VALIDATION_FAILED", result.ErrorCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("A")]
    public async Task CreateTenantAsync_InvalidDisplayName_ReturnsValidationFailed(string invalidDisplayName)
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var request = new CreateTenantRequest("acme-corp", invalidDisplayName);

        var result = await service.CreateTenantAsync(Guid.NewGuid(), request);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("VALIDATION_FAILED", result.ErrorCode);
    }

    [Fact]
    public async Task UnimplementedMethods_ThrowNotImplementedException()
    {
        var context = CreateDummyContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);

        await Assert.ThrowsAsync<NotImplementedException>(() => service.GetTenantByIdAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<NotImplementedException>(() => service.GetTenantBySlugAsync("acme"));
        await Assert.ThrowsAsync<NotImplementedException>(() => service.UpdateTenantAsync(Guid.NewGuid(), new UpdateTenantRequest("New")));
        await Assert.ThrowsAsync<NotImplementedException>(() => service.ActivateTenantAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<NotImplementedException>(() => service.SuspendTenantAsync(Guid.NewGuid(), "reason"));
        await Assert.ThrowsAsync<NotImplementedException>(() => service.DeactivateTenantAsync(Guid.NewGuid(), "reason"));
    }
}
