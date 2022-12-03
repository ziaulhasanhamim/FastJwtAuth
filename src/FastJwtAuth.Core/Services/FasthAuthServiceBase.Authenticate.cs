namespace FastJwtAuth.Core.Services;

public abstract partial class FastAuthServiceBase<TUser, TRefreshToken, TUserKey>
{
    public async Task<AuthResult<TUser>> AuthenticateWithMail(string email, string password, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokenCreationOptions.SigningCredentials);
        var user = await GetUserByEmail(email, cancellationToken);
        if (user is null)
        {
            List<string> validationErrors = new() { FastAuthErrorCodes.WrongEmail };
            return new AuthResult<TUser>.Failure(validationErrors);
        }

        var passwordMatched = VerifyPassword(password, user.PasswordHash!);
        if (!passwordMatched)
        {
            List<string> validationErrors = new() { FastAuthErrorCodes.WrongPassword };
            return new AuthResult<TUser>.Failure(validationErrors);
        }

        user.LastLogin = DateTime.UtcNow;
        await UpdateUserLastLogin(user, cancellationToken);

        var result = await GenerateTokens(user!, tokenCreationOptions, cancellationToken);

        await CommitDbChanges(cancellationToken);

        return result;
    }

    public Task<AuthResult<TUser>> AuthenticateWithMail(string email, string password, CancellationToken cancellationToken = default)
    {
        if (_authOptions.DefaultTokenCreationOptions is null)
        {
            throw new ArgumentNullException(nameof(_authOptions.DefaultTokenCreationOptions), "No TokenCreationOptions was provided and DefaultTokenCreationOptions on FastAuthOptions is also null");
        }
        return AuthenticateWithMail(email, password, _authOptions.DefaultTokenCreationOptions, cancellationToken);
    }

    public async Task<AuthResult<TUser>.Success> Authenticate(TUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokenCreationOptions.SigningCredentials);
        user.LastLogin = DateTime.UtcNow;
        await UpdateUserLastLogin(user, cancellationToken);
        var result = await GenerateTokens(user!, tokenCreationOptions, cancellationToken);
        await CommitDbChanges(cancellationToken);
        return result;
    }

    public Task<AuthResult<TUser>.Success> Authenticate(TUser user, CancellationToken cancellationToken = default)
    {
        if (_authOptions.DefaultTokenCreationOptions is null)
        {
            throw new ArgumentNullException(nameof(_authOptions.DefaultTokenCreationOptions), "No TokenCreationOptions was provided and DefaultTokenCreationOptions on FastAuthOptions is also null");
        }
        return Authenticate(user, _authOptions.DefaultTokenCreationOptions, cancellationToken);
    }
}