namespace MaintenX.Api.Common.Security;

using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// EF Core implementation of <see cref="IUserSecurityStampStore"/> querying PostgreSQL via <see cref="MaintenXDbContext"/>.
/// </summary>
public sealed class EfUserSecurityStampStore : IUserSecurityStampStore
{
    private readonly MaintenXDbContext _dbContext;

    public EfUserSecurityStampStore(MaintenXDbContext dbContext)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
    }

    /// <inheritdoc />
    public async Task<UserSecurityStampRecord?> GetSecurityStampAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
        {
            return null;
        }

        return await _dbContext.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new UserSecurityStampRecord(u.SecurityStamp, u.Status))
            .SingleOrDefaultAsync(cancellationToken);
    }
}
