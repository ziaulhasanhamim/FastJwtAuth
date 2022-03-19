﻿namespace FastJwtAuth.Core.Services;

using System.IdentityModel.Tokens.Jwt;
using BCrypt = BCrypt.Net.BCrypt;

public abstract class FastUserStoreCommons<TUser, TRefreshToken, TUserKey> : IFastUserStore<TUser, TRefreshToken, TUserKey>
    where TUser : class, IFastUser<TUserKey>, new()
    where TRefreshToken : class, IFastRefreshToken<TUserKey>, new()
{
    protected readonly FastAuthOptions<TUser, TRefreshToken, TUserKey> _authOptions;
    protected readonly IFastUserValidator<TUser>? _userValidator;

    protected FastUserStoreCommons(FastAuthOptions<TUser, TRefreshToken, TUserKey> authOptions, IFastUserValidator<TUser>? userValidator)
    {
        _authOptions = authOptions;
        _userValidator = userValidator;
    }

    public virtual string NormalizeEmail(string email) => email.Normalize().ToUpperInvariant();

    public abstract Task<TRefreshToken> CreateRefreshTokenAsync(TUser user, CancellationToken cancellationToken = default);

    public abstract Task CreateUserAsync(TUser user, CancellationToken cancellationToken = default);

    public virtual IEnumerable<Claim> GetClaimsForUser(TUser user)
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

    public abstract Task<(TRefreshToken? RefreshToken, TUser? User)> GetRefreshTokenByIdAsync(string refreshTokenIdentifier, CancellationToken cancellationToken = default);

    public virtual DateTime GetRefreshTokenExpireDate(TRefreshToken refreshTokenEntity) => refreshTokenEntity.ExpiresAt;

    public virtual string GetRefreshTokenIdentifier(TRefreshToken refreshTokenEntity) => refreshTokenEntity.Id!;

    public virtual Task<TUser?> GetUserByEmailAsync(string userIdentifier, CancellationToken cancellationToken = default)
    {
        var normalizedUserIdentifier = NormalizeEmail(userIdentifier);
        return GetUserByNormalizedEmailAsync(normalizedUserIdentifier, cancellationToken);
    }

    public abstract Task<TUser?> GetUserByNormalizedEmailAsync(string normalizedUserIdentifier, CancellationToken cancellationToken = default);

    public virtual Task<bool> DoesEmailExist(string userIdentifier, CancellationToken cancellationToken = default)
    {
        var nomalizeduserIdentifier = NormalizeEmail(userIdentifier);
        return DoesNormalizedEmailExistAsync(nomalizeduserIdentifier, cancellationToken);
    }

    public abstract Task<bool> DoesNormalizedEmailExistAsync(string nomalizeduserIdentifier, CancellationToken cancellationToken = default);

    public virtual bool IsRefreshTokenExpired(TRefreshToken refreshTokenEntity) => refreshTokenEntity.ExpiresAt < DateTime.UtcNow;

    public abstract Task RemoveRefreshTokenAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken = default);

    public virtual void SetCreationDateTimes(TUser user) => user.CreatedAt = DateTime.UtcNow;

    public virtual void SetLoginDateTimes(TUser user) => user.LastLogin = DateTime.UtcNow;

    public virtual string HashPassword(string password) => BCrypt.HashPassword(password);

    public abstract Task UpdateUserAsync(TUser user, CancellationToken cancellationToken = default);

    public virtual async ValueTask<List<string>?> ValidateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
    {
        if (user.Email is null)
        {
            throw new ArgumentNullException("user.Email");
        }
        if (user.NormalizedEmail is null)
        {
            throw new ArgumentNullException("user.NormalizedEmail");
        }
        if (password is null)
        {
            throw new ArgumentNullException("password");
        }

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
            var emailExists = await DoesNormalizedEmailExistAsync(user.NormalizedEmail!, cancellationToken);
            if (emailExists)
            {
                errors ??= new();
                errors.Add(FastAuthErrorCodes.DuplicateEmail);
            }
        }
        return errors;
    }

    public virtual bool VerifyPassword(string rawPassword, string hashedPassword) => 
        BCrypt.Verify(rawPassword, hashedPassword);
}
