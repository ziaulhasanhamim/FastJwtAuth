namespace FastJwtAuth.Core.Services;

using Microsoft.IdentityModel.Tokens;


public class FastAuthService<TUser, TRefreshToken, TUserKey> : IFastAuthService<TUser, TRefreshToken, TUserKey>
    where TUser : class, IFastUser<TUserKey>, new()
    where TRefreshToken : class, IFastRefreshToken<TUserKey>, new()
{
    private readonly IFastUserStore<TUser, TRefreshToken, TUserKey> _userStore;
    private readonly FastAuthOptions _authOptions;

    public FastAuthService(IFastUserStore<TUser, TRefreshToken, TUserKey> userStore, FastAuthOptions authOptions)
    {
        _userStore = userStore;
        _authOptions = authOptions;
    }

    public ValueTask<List<AuthErrorType>?> ValidateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
    {
        if (user.NormalizedEmail is null)
        {
            user.NormalizedEmail = _userStore.NormalizeEmail(user.Email ?? throw new ArgumentNullException("user.Email"));
        }
        return _userStore.ValidateUserAsync(user, password, cancellationToken);
    }

    public async Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, bool validateUser, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
    {
        if (validateUser)
        {
            var validation_errors = await ValidateUserAsync(user, password, cancellationToken);
            if (validation_errors is not null)
            {
                return new FailureAuthResult<TUser>(validation_errors);
            }
        }

        _userStore.SetPassword(user, password);

        user.CreatedAt = DateTime.UtcNow;
        user.LastLogin = user.CreatedAt;

        await _userStore.CreateUserAsync(user, cancellationToken);
        return await generateTokens(user!, signingCredentials, cancellationToken);
    }

    public Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, bool validateUser, CancellationToken cancellationToken = default)
    {
        return CreateUserAsync(user, password, validateUser, null, cancellationToken);
    }

    public Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
    {
        return CreateUserAsync(user, password, true, cancellationToken);
    }

    public async Task<IAuthResult<TUser>> LoginUserAsync(string email, string password, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
    {
        var user = await _userStore.GetUserByEmailAsync(email, cancellationToken);
        if (user is null)
        {
            List<AuthErrorType> validationErrors = new() { AuthErrorType.WrongEmail };
            return new FailureAuthResult<TUser>(validationErrors);
        }

        var passwordMatched = _userStore.VerifyPassword(user, password);
        if (!passwordMatched)
        {
            List<AuthErrorType> validationErrors = new() { AuthErrorType.WrongPassword };
            return new FailureAuthResult<TUser>(validationErrors);
        }

        user.LastLogin = DateTime.UtcNow;
        await _userStore.UpdateUserAsync(user, cancellationToken);

        return await generateTokens(user!, signingCredentials, cancellationToken);
    }

    public Task<IAuthResult<TUser>> LoginUserAsync(string email, string password, CancellationToken cancellationToken = default)
    {
        return LoginUserAsync(email, password, null, cancellationToken);
    }

    public async Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
    {
        if (refreshToken is null)
        {
            throw new ArgumentNullException(nameof(refreshToken));
        }
        if (!_authOptions.UseRefreshToken)
        {
            throw new NotImplementedException("FastJwtAuth.Core.Options.FastAuthOptions.UseRefreshToken is false. make it true for refresh");
        }
        var (refreshTokenEntity, user) = await _userStore.GetRefreshTokenByIdAsync(refreshToken, cancellationToken);
        if (refreshTokenEntity is null)
        {
            return new FailureAuthResult<TUser>(new() { AuthErrorType.InvalidRefreshToken });
        }
        if (refreshTokenEntity.ExpiresAt < DateTime.UtcNow)
        {
            return new FailureAuthResult<TUser>(new() { AuthErrorType.ExpiredRefreshToken });
        }
        await _userStore.RemoveRefreshTokenAsync(refreshTokenEntity, cancellationToken);
        var succResult = await generateTokens(user!, signingCredentials, cancellationToken);
        return succResult;
    }

    public Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        return RefreshAsync(refreshToken, null, cancellationToken);
    }

    private async Task<SuccessAuthResult<TUser>> generateTokens(TUser user, SigningCredentials? signingCredentials, CancellationToken cancellationToken)
    {
        string? refreshToken = null;
        DateTime? refreshTokenExpireDate = null;
        if (_authOptions.UseRefreshToken)
        {
            TRefreshToken refreshTokenEntity = await _userStore.CreateRefreshTokenAsync(user, cancellationToken);
            refreshToken = refreshTokenEntity.Id;
            refreshTokenExpireDate = refreshTokenEntity.ExpiresAt;
        }
        signingCredentials ??= _authOptions.DefaultSigningCredentials;
        if (signingCredentials is null)
        {
            throw new ArgumentException("No SigningCredentials was provided and DefaultSigningCredentials on FastAuthOptions is also null");
        }
        var claims = _userStore.GetClaimsForUser(user);
        JwtSecurityToken securityToken = new(
            claims: claims,
            expires: DateTime.UtcNow.Add(_authOptions.AccessTokenLifeSpan),
            signingCredentials: signingCredentials);
        var accessToken = new JwtSecurityTokenHandler().WriteToken(securityToken);
        return new(
            accessToken,
            securityToken.ValidTo,
            refreshToken,
            refreshTokenExpireDate,
            user);
    }
}
