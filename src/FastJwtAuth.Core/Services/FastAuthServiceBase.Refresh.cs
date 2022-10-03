namespace FastJwtAuth.Core.Services;

public abstract partial class FastAuthServiceBase<TUser, TRefreshToken, TUserKey>
{
    public async Task<AuthResult<TUser>> Refresh(string refreshToken, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokenCreationOptions.SigningCredentials);

        if (!_authOptions.UseRefreshToken)
        {
            throw new NotImplementedException("FastJwtAuth.Core.Options.FastAuthOptions.UseRefreshToken is false. make it true for refresh");
        }
        var (refreshTokenEntity, user) = await GetRefreshTokenById(refreshToken, cancellationToken);
        if (refreshTokenEntity is null)
        {
            return new AuthResult<TUser>.Failure(new() { FastAuthErrorCodes.InvalidRefreshToken });
        }
        if (refreshTokenEntity.ExpiresAt < DateTime.UtcNow)
        {
            return new AuthResult<TUser>.Failure(new() { FastAuthErrorCodes.ExpiredRefreshToken });
        }
        await RemoveRefreshToken(refreshTokenEntity, cancellationToken);
        var successResult = await GenerateTokens(user!, tokenCreationOptions, cancellationToken);
        await CommitDbChanges(cancellationToken);
        return successResult;
    }

    public Task<AuthResult<TUser>> Refresh(string refreshToken, CancellationToken cancellationToken = default)
    {
        if (_authOptions.DefaultTokenCreationOptions is null)
        {
            throw new ArgumentNullException(nameof(_authOptions.DefaultTokenCreationOptions), "No TokenCreationOptions was provided and DefaultTokenCreationOptions on FastAuthOptions is also null");
        }
        return Refresh(refreshToken, _authOptions.DefaultTokenCreationOptions, cancellationToken);
    }
}