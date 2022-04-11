namespace FastJwtAuth.Core.Services;

using Microsoft.IdentityModel.Tokens;


public abstract class FastAuthServiceBase<TUser, TRefreshToken, TUserKey> : IFastAuthService<TUser, TRefreshToken, TUserKey>
    where TUser : class, IFastUser<TUserKey>, new()
    where TRefreshToken : class, IFastRefreshToken<TUserKey>, new()
{
    protected readonly FastAuthOptions<TUser, TRefreshToken, TUserKey> _authOptions;
    protected readonly IFastUserValidator<TUser> _userValidator;

    public FastAuthServiceBase(FastAuthOptions<TUser, TRefreshToken, TUserKey> authOptions, IFastUserValidator<TUser> userValidator)
    {
        _authOptions = authOptions;
        _userValidator = userValidator;
    }

    public async Task<CreateUserResult> CreateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
    {
        user.NormalizedEmail ??= NormalizeText(user.Email ?? throw new ArgumentNullException("user.Email"));

        var validationErrors = await validateUserAsync(user, password, cancellationToken);
        if (validationErrors is not null)
        {
            return new(false, validationErrors);
        }

        user.PasswordHash ??= HashPassword(password);

        user.CreatedAt = DateTime.UtcNow;
        user.LastLogin = user.CreatedAt;

        await addUserAsync(user, cancellationToken);
        return new(true, null);
    }

    public async Task<AuthResult<TUser>> AuthenticateAsync(string email, string password, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
    {
        var user = await getUserByEmailAsync(email, cancellationToken);
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
        await updateUserAsync(user, cancellationToken);

        return await generateTokens(user!, signingCredentials, cancellationToken);
    }

    public Task<AuthResult<TUser>> AuthenticateAsync(string email, string password, CancellationToken cancellationToken = default)
    {
        return AuthenticateAsync(email, password, null, cancellationToken);
    }

    public async Task<AuthResult<TUser>.Success> AuthenticateAsync(TUser user, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
    {
        user.LastLogin = DateTime.UtcNow;
        await updateUserAsync(user, cancellationToken);
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
        var (refreshTokenEntity, user) = await getRefreshTokenByIdAsync(refreshToken, cancellationToken);
        if (refreshTokenEntity is null)
        {
            return new AuthResult<TUser>.Failure(new() { FastAuthErrorCodes.InvalidRefreshToken });
        }
        if (refreshTokenEntity.ExpiresAt < DateTime.UtcNow)
        {
            return new AuthResult<TUser>.Failure(new() { FastAuthErrorCodes.ExpiredRefreshToken });
        }
        await removeRefreshTokenAsync(refreshTokenEntity, cancellationToken);
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
            TRefreshToken refreshTokenEntity = await createRefreshTokenAsync(user, cancellationToken);
            refreshToken = refreshTokenEntity.Id;
            refreshTokenExpireDate = refreshTokenEntity.ExpiresAt;
        }
        signingCredentials ??= _authOptions.DefaultSigningCredentials;
        if (signingCredentials is null)
        {
            throw new ArgumentException("No SigningCredentials was provided and DefaultSigningCredentials on FastAuthOptions is also null");
        }
        var claims = GetClaimsForUser(user);
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

    protected virtual async ValueTask<List<string>?> validateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user.Email);
        ArgumentNullException.ThrowIfNull(user.NormalizedEmail);
        ArgumentNullException.ThrowIfNull(password);

        List<string>? errors = null;
        bool complete = false;
        if (_userValidator is not null)
        {
            (complete, errors) = await _userValidator.ValidateAsync(user, password);
        }
        if (complete)
        {
            return errors;
        }

        if (password.Length < 8)
        {
            errors ??= new();
            errors.Add(FastAuthErrorCodes.PasswordVeryShort);
        }
        var emailValidator = new EmailAddressAttribute();
        var emailValid = emailValidator.IsValid(user.Email);
        if (!emailValid)
        {
            errors ??= new();
            errors.Add(FastAuthErrorCodes.InvalidEmailFormat);
        }
        else
        {
            var emailExists = await doesNormalizedEmailExistAsync(user.NormalizedEmail!, cancellationToken);
            if (emailExists)
            {
                errors ??= new();
                errors.Add(FastAuthErrorCodes.DuplicateEmail);
            }
        }
        return errors;
    }

    public virtual bool VerifyPassword(string rawPassword, string hashedPassword) =>
        BCrypt.Net.BCrypt.Verify(rawPassword, hashedPassword);

    public virtual string HashPassword(string password) => BCrypt.Net.BCrypt.HashPassword(password);

    protected Task<TUser?> getUserByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeText(email);
        return getUserByNormalizedEmailAsync(email, cancellationToken);
    }

    protected abstract Task<TUser?> getUserByNormalizedEmailAsync(string email, CancellationToken cancellationToken);

    public virtual List<Claim> GetClaimsForUser(TUser user)
    {
        List<Claim> claims = new()
        {
            new(JwtRegisteredClaimNames.Jti, user.Id!.ToString()!),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(nameof(IFastUser<Guid>.CreatedAt), user.CreatedAt.ToString()!)
        };
        _authOptions.OnClaimsGeneration?.Invoke(claims, user);
        return claims;
    }

    protected virtual Task<bool> doesEmailExist(string email, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeText(email);
        return doesNormalizedEmailExistAsync(normalizedEmail, cancellationToken);
    }

    public string NormalizeText(string text) => text.Normalize().ToUpperInvariant();

    protected abstract Task updateUserAsync(TUser user, CancellationToken cancellationToken);

    protected abstract Task removeRefreshTokenAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken);

    protected abstract Task<(TRefreshToken? RefreshToken, TUser? User)> getRefreshTokenByIdAsync(string id, CancellationToken cancellationToken);

    protected abstract Task<TRefreshToken> createRefreshTokenAsync(TUser user, CancellationToken cancellationToken);

    protected abstract Task addUserAsync(TUser user, CancellationToken cancellationToken);

    protected abstract Task<bool> doesNormalizedEmailExistAsync(string normalizedEmail, CancellationToken cancellationToken);
}
