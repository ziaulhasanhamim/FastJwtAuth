namespace FastJwtAuth.EFCore.Services;

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
        IFastUserValidator<TUser> userValidator)
        : base(authOptions, userValidator)
    {
        _dbContext = dbContext;
    }

    protected override async Task addUserAsync(TUser user, CancellationToken cancellationToken)
    {
        await _dbContext.AddAsync(user, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    protected override async Task<TRefreshToken> createRefreshTokenAsync(TUser user, CancellationToken cancellationToken)
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

    protected override Task<bool> doesNormalizedEmailExistAsync(string nomalizedEmail, CancellationToken cancellationToken = default) =>
        _dbContext.Set<TUser>()
            .Where(user => user.NormalizedEmail == nomalizedEmail)
            .AnyAsync(cancellationToken);

    protected override async Task<(TRefreshToken? RefreshToken, TUser? User)> getRefreshTokenByIdAsync(
        string id, 
        CancellationToken cancellationToken)
    {
        var refreshToken = await _dbContext.Set<TRefreshToken>()
            .Where(token => token.Id == id)
            .Include(token => token.User)
            .FirstOrDefaultAsync(cancellationToken);
        return (refreshToken, refreshToken?.User);
    }

    protected override Task<TUser?> getUserByNormalizedEmailAsync(
        string normalizedEmail, 
        CancellationToken cancellationToken) =>
        _dbContext.Set<TUser>()
            .Where(user => user.NormalizedEmail == normalizedEmail)
            .FirstOrDefaultAsync(cancellationToken)!;

    protected override Task removeRefreshTokenAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken)
    {
        _dbContext.Remove(refreshTokenEntity);
        return _dbContext.SaveChangesAsync(cancellationToken);
    }

    protected override Task updateUserAsync(TUser user, CancellationToken cancellationToken)
    {
        _dbContext.Update(user);
        return _dbContext.SaveChangesAsync(cancellationToken);
    }
}