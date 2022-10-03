namespace FastJwtAuth.Core.Services;

public abstract partial class FastAuthServiceBase<TUser, TRefreshToken, TUserKey>
{
    protected Task<TUser?> GetUserByEmail(string email, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeText(email);
        return GetUserByNormalizedEmail(normalizedEmail, cancellationToken);
    }

    protected Task<bool> DoesEmailExist(string email, CancellationToken ct = default)
    {
        var normalizedEmail = NormalizeText(email);
        return DoesNormalizedEmailExist(normalizedEmail, ct);
    }

    protected abstract Task<bool> DoesNormalizedUsernameExist(string normalizedUsername, CancellationToken cancellationToken);

    protected abstract Task UpdateUserLastLogin(TUser user, CancellationToken cancellationToken);

    protected abstract Task RemoveRefreshToken(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken);

    protected abstract Task<(TRefreshToken? RefreshToken, TUser? User)> GetRefreshTokenById(string id, CancellationToken cancellationToken);

    protected abstract ValueTask<TRefreshToken> CreateRefreshToken(TUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken);

    protected abstract Task AddUser(TUser user, CancellationToken cancellationToken);

    protected abstract Task<bool> DoesNormalizedEmailExist(string normalizedEmail, CancellationToken cancellationToken);

    protected abstract Task CommitDbChanges(CancellationToken cancellationToken);

    protected abstract Task<TUser?> GetUserByNormalizedEmail(string normalizedEmail, CancellationToken cancellationToken);
}