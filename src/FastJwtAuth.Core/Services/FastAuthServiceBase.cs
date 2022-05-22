  namespace FastJwtAuth.Core.Services;

using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;


public abstract class FastAuthServiceBase<TUser, TRefreshToken, TUserKey> : IFastAuthService<TUser, TRefreshToken, TUserKey>
    where TUser : class, IFastUser<TUserKey>, new()
    where TRefreshToken : class, IFastRefreshToken<TUserKey>, new()
{
    protected readonly FastAuthOptions<TUser, TRefreshToken, TUserKey> _authOptions;
    protected readonly IFastUserValidator<TUser>? _userValidator;

    public const string UsernameValidationRegex = @"^[a-zA-Z0-9]([-._](?![-._])|[a-zA-Z0-9])*[a-zA-Z0-9]$";

    private static readonly Regex _usernameValidationRegex = new(UsernameValidationRegex, RegexOptions.Compiled);

    private readonly static EmailAddressAttribute _emailValidator = new();
    private readonly static JwtSecurityTokenHandler _jwtSecurityTokenHandler = new();

    public FastAuthServiceBase(FastAuthOptions<TUser, TRefreshToken, TUserKey> authOptions, IFastUserValidator<TUser>? userValidator)
    {
        _authOptions = authOptions;
        _userValidator = userValidator;
    }

    public async Task<CreateUserResult> CreateUser(TUser user, string password, CancellationToken cancellationToken = default)
    {
        Guard.IsNotNull(user.Email);
        Guard.IsNotNull(password);
        if (_authOptions.IsUsernameCompulsory)
        {
            Guard.IsNotNull(user.Username);
        }
        user.NormalizedEmail ??= NormalizeText(user.Email);
        if (user.Username is not null)
        {
            user.NormalizedUsername ??= NormalizeText(user.Username);
        }

        var validationErrors = await validateUser(user, password, cancellationToken);
        
        if (validationErrors is not null)
        {
            return new(false, validationErrors);
        }

        user.PasswordHash ??= HashPassword(password);

        user.CreatedAt = DateTime.UtcNow;
        user.LastLogin = user.CreatedAt;

        await addUser(user, cancellationToken);
        await commitDbChanges(cancellationToken);
        return new(true, null);
    }

    public async Task<AuthResult<TUser>> Authenticate(string email, string password, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokenCreationOptions.SigningCredentials);
        var user = await getUserByEmail(email, cancellationToken);
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
        await updateUserLastLogin(user, cancellationToken);

        var result = await generateTokens(user!, tokenCreationOptions, cancellationToken);

        await commitDbChanges(cancellationToken);

        return result;
    }

    public Task<AuthResult<TUser>> Authenticate(string email, string password, CancellationToken cancellationToken = default)
    {
        if (_authOptions.DefaultTokenCreationOptions is null)
        {
            throw new ArgumentNullException(nameof(_authOptions.DefaultTokenCreationOptions), "No TokenCreationOptions was provided and DefaultTokenCreationOptions on FastAuthOptions is also null");
        }
        return Authenticate(email, password, _authOptions.DefaultTokenCreationOptions, cancellationToken);
    }

    public async Task<AuthResult<TUser>.Success> Authenticate(TUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokenCreationOptions.SigningCredentials);
        user.LastLogin = DateTime.UtcNow;
        await updateUserLastLogin(user, cancellationToken);
        var result = await generateTokens(user!, tokenCreationOptions, cancellationToken);
        await commitDbChanges(cancellationToken);
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

    public async Task<AuthResult<TUser>> Refresh(string refreshToken, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokenCreationOptions.SigningCredentials);

        if (!_authOptions.UseRefreshToken)
        {
            throw new NotImplementedException("FastJwtAuth.Core.Options.FastAuthOptions.UseRefreshToken is false. make it true for refresh");
        }
        var (refreshTokenEntity, user) = await getRefreshTokenById(refreshToken, cancellationToken);
        if (refreshTokenEntity is null)
        {
            return new AuthResult<TUser>.Failure(new() { FastAuthErrorCodes.InvalidRefreshToken });
        }
        if (refreshTokenEntity.ExpiresAt < DateTime.UtcNow)
        {
            return new AuthResult<TUser>.Failure(new() { FastAuthErrorCodes.ExpiredRefreshToken });
        }
        await removeRefreshToken(refreshTokenEntity, cancellationToken);
        var successResult = await generateTokens(user!, tokenCreationOptions, cancellationToken);
        await commitDbChanges(cancellationToken);
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

    private async Task<AuthResult<TUser>.Success> generateTokens(TUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken)
    {
        string? refreshToken = null;
        DateTime? refreshTokenExpireDate = null;
        if (_authOptions.UseRefreshToken)
        {
            TRefreshToken refreshTokenEntity = await createRefreshToken(user, tokenCreationOptions, cancellationToken);
            refreshToken = refreshTokenEntity.Id;
            refreshTokenExpireDate = refreshTokenEntity.ExpiresAt;
        }

        var claims = GetClaimsForUser(user);
        JwtSecurityToken securityToken = new(
            claims: claims,
            expires: DateTime.UtcNow.Add(tokenCreationOptions.AccessTokenLifeSpan),
            signingCredentials: tokenCreationOptions.SigningCredentials,
            issuer: tokenCreationOptions.Issuer,
            audience: tokenCreationOptions.Audience);
        var accessToken = _jwtSecurityTokenHandler.WriteToken(securityToken);
        return new(
            accessToken,
            securityToken.ValidTo,
            refreshToken,
            refreshTokenExpireDate,
            user);
    }

    protected virtual async ValueTask<List<string>?> validateUser(TUser user, string password, CancellationToken cancellationToken = default)
    {
        List<string>? errors = null;
        bool complete = false;
        if (_userValidator is not null)
        {
            (complete, errors) = await _userValidator.Validate(user, password);
        }
        if (complete)
        {
            return errors;
        }
        errors = validatePassword(password, errors);
        errors = await validateEmail(user, errors, cancellationToken);
        if (user.Username is not null)
        {
            errors = await validateUsername(user, errors, cancellationToken);
        }
        return errors;
    }

    private List<string>? validatePassword(string password, List<string>? errors)
    {
        if (password.Length < _authOptions.PasswordMinLength)
        {
            errors ??= new();
            errors.Add(FastAuthErrorCodes.PasswordVeryShort);
        }
        else if (_authOptions.PasswordMaxLength.HasValue && password.Length < _authOptions.PasswordMaxLength.Value)
        {
            errors ??= new();
            errors.Add(FastAuthErrorCodes.PasswordVeryLong);
        }
        return errors;
    }

    private async ValueTask<List<string>?> validateEmail(TUser user, List<string>? errors, CancellationToken cancellationToken)
    {
        var emailValid = _emailValidator.IsValid(user.Email);
        if (!emailValid)
        {
            errors ??= new();
            errors.Add(FastAuthErrorCodes.InvalidEmailFormat);
        }
        else
        {
            var emailExists = await doesNormalizedEmailExist(user.NormalizedEmail!, cancellationToken);
            if (emailExists)
            {
                errors ??= new();
                errors.Add(FastAuthErrorCodes.DuplicateEmail);
            }
        }
        return errors;
    }

    private async ValueTask<List<string>?> validateUsername(TUser user, List<string>? errors, CancellationToken cancellationToken)
    {
        if (user.Username!.Length < _authOptions.UsernameMinLength)
        {
            errors ??= new();
            errors.Add(FastAuthErrorCodes.UsernameVeryShort);
        }
        else if (_authOptions.UsernameMaxLength.HasValue && user.Username.Length > _authOptions.UsernameMaxLength.Value)
        {
            errors ??= new();
            errors.Add(FastAuthErrorCodes.UsernameVeryLong);
        }
        else if (!_usernameValidationRegex.IsMatch(user.Username))
        {
            errors ??= new();
            errors.Add(FastAuthErrorCodes.InvalidUsernameFormat);
        }
        else
        {
            var usernameExists = await doesNormalizedUsernameExist(user.NormalizedUsername!, cancellationToken);
            if (usernameExists)
            {
                errors ??= new();
                errors.Add(FastAuthErrorCodes.DuplicateUsername);
            }
        }
        return errors;
    }

    protected abstract Task<bool> doesNormalizedUsernameExist(string normalizedUsername, CancellationToken cancellationToken);

    public virtual bool VerifyPassword(string rawPassword, string hashedPassword) =>
        BCrypt.Net.BCrypt.Verify(rawPassword, hashedPassword);

    public virtual string HashPassword(string password) => BCrypt.Net.BCrypt.HashPassword(password);

    protected Task<TUser?> getUserByEmail(string email, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeText(email);
        return getUserByNormalizedEmail(normalizedEmail, cancellationToken);
    }

    protected abstract Task<TUser?> getUserByNormalizedEmail(string normalizedEmail, CancellationToken cancellationToken);

    public virtual List<Claim> GetClaimsForUser(TUser user)
    {
        List<Claim> claims = new()
        {
            new(JwtRegisteredClaimNames.Sub, user.Id!.ToString()!),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(nameof(IFastUser<Guid>.CreatedAt), user.CreatedAt.ToString()!)
        };
        if (user.Username is not null)
        {
            claims.Add(new(JwtRegisteredClaimNames.UniqueName, user.Username));
        }
        _authOptions.GenerateClaims?.Invoke(claims, user);
        return claims;
    }

    protected virtual Task<bool> doesEmailExist(string email, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = NormalizeText(email);
        return doesNormalizedEmailExist(normalizedEmail, cancellationToken);
    }

    public string NormalizeText(string text) => text.Normalize().ToUpperInvariant();

    protected abstract Task updateUserLastLogin(TUser user, CancellationToken cancellationToken);

    protected abstract Task removeRefreshToken(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken);

    protected abstract Task<(TRefreshToken? RefreshToken, TUser? User)> getRefreshTokenById(string id, CancellationToken cancellationToken);

    protected abstract ValueTask<TRefreshToken> createRefreshToken(TUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken);

    protected abstract Task addUser(TUser user, CancellationToken cancellationToken);

    protected abstract Task<bool> doesNormalizedEmailExist(string normalizedEmail, CancellationToken cancellationToken);

    protected abstract Task commitDbChanges(CancellationToken cancellationToken);
}
