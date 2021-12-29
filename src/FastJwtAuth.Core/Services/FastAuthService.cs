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

    public async Task<CreateUserResult> CreateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
    {
        user.NormalizedEmail ??= NormalizeEmail(user.Email ?? throw new ArgumentNullException("user.Email"));

        var validationErrors = await _userStore.ValidateUserAsync(user, password, cancellationToken);
        if (validationErrors is not null)
        {
            return new(false, validationErrors);
        }

        user.PasswordHash ??= HashPassword(password);

        user.CreatedAt = DateTime.UtcNow;
        user.LastLogin = user.CreatedAt;

        await _userStore.CreateUserAsync(user, cancellationToken);
        return new(true, null);
    }

    public string NormalizeEmail(string email) => _userStore.NormalizeEmail(email);

    public string HashPassword(string password) => _userStore.HashPassword(password);

    public async Task<AuthResult<TUser>> AuthenticateAsync(string email, string password, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
    {
        var user = await _userStore.GetUserByEmailAsync(email, cancellationToken);
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
        await _userStore.UpdateUserAsync(user, cancellationToken);

        return await generateTokens(user!, signingCredentials, cancellationToken);
    }

    public bool VerifyPassword(string rawPassword, string hashedPassword) =>
        _userStore.VerifyPassword(rawPassword, hashedPassword);

    public Task<AuthResult<TUser>> AuthenticateAsync(string email, string password, CancellationToken cancellationToken = default)
    {
        return AuthenticateAsync(email, password, null, cancellationToken);
    }

    public async Task<AuthResult<TUser>.Success> AuthenticateAsync(TUser user, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
    {
        user.LastLogin = DateTime.UtcNow;
        await _userStore.UpdateUserAsync(user, cancellationToken);
        return await generateTokens(user!, signingCredentials, cancellationToken);
    }

    public Task<AuthResult<TUser>.Success> AuthenticateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        return AuthenticateAsync(user, null, cancellationToken);
    }

    public async Task<AuthResult<TUser>> RefreshAsync(string refreshToken, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
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
            return new AuthResult<TUser>.Failure(new() { FastAuthErrorCodes.InvalidRefreshToken });
        }
        if (refreshTokenEntity.ExpiresAt < DateTime.UtcNow)
        {
            return new AuthResult<TUser>.Failure(new() { FastAuthErrorCodes.ExpiredRefreshToken });
        }
        await _userStore.RemoveRefreshTokenAsync(refreshTokenEntity, cancellationToken);
        var succResult = await generateTokens(user!, signingCredentials, cancellationToken);
        return succResult;
    }

    public Task<AuthResult<TUser>> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        return RefreshAsync(refreshToken, null, cancellationToken);
    }

    private async Task<AuthResult<TUser>.Success> generateTokens(TUser user, SigningCredentials? signingCredentials, CancellationToken cancellationToken)
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
