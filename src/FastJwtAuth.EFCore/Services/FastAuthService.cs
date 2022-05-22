namespace FastJwtAuth.EFCore.Services;

using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FastJwtAuth;
using FastJwtAuth.Core.Services;

public class FastAuthService<TUser, TRefreshToken, TDbContext> 
    : FastAuthServiceBase<TUser, TRefreshToken, Guid>, IFastAuthService<TUser, TRefreshToken>
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
    where TDbContext : DbContext
{
    private readonly TDbContext _dbContext;
    public FastAuthService(
        TDbContext dbContext,
        EFCoreFastAuthOptions<TUser, TRefreshToken> authOptions,
        IFastUserValidator<TUser>? userValidator = null)
        : base(authOptions, userValidator)
    {
        _dbContext = dbContext;
    }

    protected override async Task addUser(TUser user, CancellationToken cancellationToken)
    {
        await _dbContext.AddAsync(user, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    protected override async ValueTask<TRefreshToken> createRefreshToken(TUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken)
    {
        var randomBytes = ArrayPool<byte>.Shared.Rent(tokenCreationOptions.RefreshTokenBytesLength);
        using var rng = RandomNumberGenerator.Create();
        
        rng.GetBytes(randomBytes);

        var utcNow = DateTime.UtcNow;
        TRefreshToken refreshToken = new()
        {
            Id = Convert.ToBase64String(randomBytes),
            CreatedAt = utcNow,
            ExpiresAt = utcNow.Add(tokenCreationOptions.RefreshTokenLifeSpan),
            UserId = user!.Id
        };
        ArrayPool<byte>.Shared.Return(randomBytes);
        await _dbContext.AddAsync(refreshToken, cancellationToken);

        return refreshToken;
    }

    protected override Task<bool> doesNormalizedEmailExist(string nomalizedEmail, CancellationToken cancellationToken = default) =>
        _dbContext.Set<TUser>()
            .AnyAsync(user => user.NormalizedEmail == nomalizedEmail, cancellationToken);

    protected override async Task<(TRefreshToken? RefreshToken, TUser? User)> getRefreshTokenById(
        string id, 
        CancellationToken cancellationToken)
    {
        var refreshToken = await _dbContext.Set<TRefreshToken>()
            .AsNoTracking()
            .Include(token => token.User)
            .FirstOrDefaultAsync(token => token.Id == id, cancellationToken);
        return (refreshToken, refreshToken?.User);
    }

    protected override Task<TUser?> getUserByNormalizedEmail(
        string normalizedEmail, 
        CancellationToken cancellationToken) =>
        _dbContext.Set<TUser>()
            .AsNoTracking()
            .FirstOrDefaultAsync(user => user.NormalizedEmail == normalizedEmail, cancellationToken)!;

    protected override Task removeRefreshToken(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken)
    {
        _dbContext.Remove(refreshTokenEntity);
        return Task.CompletedTask;
    }

    protected override Task updateUserLastLogin(TUser user, CancellationToken cancellationToken)
    {
        var entry = _dbContext.Entry(user);
        entry.Property(nameof(user.LastLogin));
        return Task.CompletedTask;
    }

    protected override Task commitDbChanges(CancellationToken cancellationToken)
    {
        return _dbContext.SaveChangesAsync(cancellationToken);
    }

    protected override Task<bool> doesNormalizedUsernameExist(string normalizedUsername, CancellationToken cancellationToken) => 
        _dbContext.Set<TUser>()
            .AnyAsync(user => user.NormalizedUsername == normalizedUsername, cancellationToken);
}