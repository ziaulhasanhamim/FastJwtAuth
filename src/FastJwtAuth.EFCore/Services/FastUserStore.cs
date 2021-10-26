namespace FastJwtAuth.EFCore.Services;

using System.Security.Cryptography;

public class FastUserStore<TUser, TUserKey, TRefreshToken, TDbContext> : FastUserStoreCommons<TUser, TRefreshToken, TUserKey>
    where TUser : FastUser<TUserKey>, new()
    where TRefreshToken : FastRefreshToken<TUser, TUserKey>, new()
    where TDbContext : DbContext
{
    protected readonly TDbContext _dbContext;

    public FastUserStore(TDbContext dbContext, FastAuthOptions authOptions, IFastUserValidator<TUser>? userValidator = null)
        : base(authOptions, userValidator)
    {
        _dbContext = dbContext;
    }

    public override Task<bool> DoesNormalizedUserIdentifierExistAsync(string nomalizeduserIdentifier, CancellationToken cancellationToken = default) =>
        _dbContext.Set<TUser>()
            .Where(user => user.NormalizedEmail == nomalizeduserIdentifier)
            .AnyAsync(cancellationToken);

    public override async Task<TRefreshToken> CreateRefreshTokenAsync(TUser user, CancellationToken cancellationToken = default)
    {
        var randomBytes = new byte[_authOptions.RefreshTokenBytesLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        TRefreshToken refreshToken = new()
        {
            Id = Convert.ToBase64String(randomBytes),
            ExpiresAt = DateTime.UtcNow.Add(_authOptions.RefreshTokenLifeSpan),
            UserId = user!.Id
        };

        await _dbContext.AddAsync(refreshToken, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return refreshToken;
    }

    public override async Task CreateUserAsync(TUser user, CancellationToken cancellationToken = default)
    {
        await _dbContext.AddAsync(user, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public override async Task<(TRefreshToken? RefreshToken, TUser? User)> GetRefreshTokenByIdentifierAsync(string refreshTokenIdentifier, CancellationToken cancellationToken = default)
    {
        var refreshToken = await _dbContext.Set<TRefreshToken>()
            .Where(token => token.Id == refreshTokenIdentifier)
            .Include(token => token.User)
            .FirstOrDefaultAsync(cancellationToken);
        return (refreshToken, refreshToken?.User);
    }

    public override Task<TUser?> GetUserByNormalizedIdentifierAsync(string normalizedUserIdentifier, CancellationToken cancellationToken = default) =>
        _dbContext.Set<TUser>()
            .Where(user => user.NormalizedEmail == normalizedUserIdentifier)
            .FirstOrDefaultAsync(cancellationToken)!;

    public override Task MakeRefreshTokenUsedAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken = default)
    {
        _dbContext.Remove(refreshTokenEntity);
        return _dbContext.SaveChangesAsync(cancellationToken);
    }

    public override Task UpdateUserAsync(TUser user, CancellationToken cancellationToken = default)
    {
        _dbContext.Update(user);
        return _dbContext.SaveChangesAsync(cancellationToken);
    }
}
