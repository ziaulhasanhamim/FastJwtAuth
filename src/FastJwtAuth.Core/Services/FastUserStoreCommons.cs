using FastJwtAuth.Core.Entities;
using FastJwtAuth;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace FastJwtAuth.Core.Services
{
    public abstract class FastUserStoreCommons<TUser, TRefreshToken, TKey> : IFastUserStore<TUser, TRefreshToken>
        where TUser : class, IFastUser<TKey>
        where TRefreshToken : class, IFastRefreshToken<TKey>
    {
        protected readonly FastAuthOptions _authOptions;

        protected FastUserStoreCommons(FastAuthOptions authOptions)
        {
            _authOptions = authOptions;
        }

        protected abstract object getDbAccessor();

        public virtual string NormalizeUserIdentifier(string identifier) => identifier.Normalize().ToUpperInvariant();

        public abstract Task<TRefreshToken> CreateRefreshTokenAsync(TUser? user, CancellationToken cancellationToken = default);

        public abstract Task CreateUserAsync(TUser user, CancellationToken cancellationToken = default);

        public abstract IEnumerable<Claim> GetClaimsForUser(TUser user);

        public abstract Task<(TRefreshToken? RefreshToken, TUser? User)> GetRefreshTokenByIdentifierAsync(string refreshTokenIdentifier, CancellationToken cancellationToken = default);

        public virtual DateTime GetRefreshTokenExpireDate(TRefreshToken refreshTokenEntity) => refreshTokenEntity.ExpiresAt;

        public virtual string GetRefreshTokenIdentifier(TRefreshToken refreshTokenEntity) => refreshTokenEntity.Id!;

        public virtual Task<TUser?> GetUserByIdentifierAsync(string userIdentifier, CancellationToken cancellationToken = default)
        {
            var normalizedUserIdentifier = NormalizeUserIdentifier(userIdentifier);
            return GetUserByNormalizedIdentifier(normalizedUserIdentifier, cancellationToken);
        }

        public abstract Task<TUser?> GetUserByNormalizedIdentifier(string normalizedUserIdentifier, CancellationToken cancellationToken = default);

        public virtual Task<bool> DoesUserIdentifierExist(string userIdentifier, CancellationToken cancellationToken = default)
        {
            var nomalizeduserIdentifier = NormalizeUserIdentifier(userIdentifier);
            return DoesNormalizedUserIdentifierExist(nomalizeduserIdentifier, cancellationToken);
        }

        public abstract Task<bool> DoesNormalizedUserIdentifierExist(string nomalizeduserIdentifier, CancellationToken cancellationToken = default);

        public virtual bool IsRefreshTokenExpired(TRefreshToken refreshTokenEntity) => refreshTokenEntity.ExpiresAt < DateTime.UtcNow;

        public abstract bool IsRefreshTokenUsed(TRefreshToken refreshTokenEntity);

        public abstract Task MakeRefreshTokenUsedAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken = default);

        public virtual void SetCreationDateTimes(TUser user) => user.CreatedAt = DateTime.UtcNow;

        public virtual void SetLoginDateTimes(TUser user) => user.LastLogin = DateTime.UtcNow;

        public virtual void SetNormalizedFields(TUser user)
        {
            user.NormalizedEmail = NormalizeUserIdentifier(user.Email!);
        }

        public virtual void SetPassword(TUser user, string password) => user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(password);

        public abstract Task UpdateUserAsync(TUser user, CancellationToken cancellationToken = default);

        public virtual async Task<Dictionary<string, List<string>>?> ValidateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
        {
            Dictionary<string, List<string>>? errors = null;
            if (_authOptions.OnUserValidate is not null)
            {
                errors = await _authOptions.OnUserValidate(user, getDbAccessor());
            }

            var emailValidator = new EmailAddressAttribute();
            var emailValid = emailValidator.IsValid(user.Email);
            if (!emailValid)
            {
                if (errors is null)
                {
                    errors = new();
                }
                if (errors.TryGetValue(nameof(IFastUser<Guid>.Email), out var emailErrors))
                {
                    emailErrors.Add("Provided email is not valid");
                }
                errors[nameof(IFastUser<Guid>.Email)] = new() { "Provided email is not valid" };
            }
            if (password.Length < 8)
            {
                if (errors is null)
                {
                    errors = new();
                }
                if (errors.TryGetValue("Password", out var passwordErrors))
                {
                    passwordErrors.Add("Password must be at least 8 characters long");
                }
                errors["Password"] = new() { "Password must be at least 8 characters long" };
            }
            if (errors is null || !errors.ContainsKey(nameof(IFastUser<Guid>.Email)))
            {
                var emailExists = await DoesNormalizedUserIdentifierExist(user.NormalizedEmail!, cancellationToken);
                if (emailExists)
                {
                    if (errors is null)
                    {
                        errors = new();
                    }
                    errors[nameof(IFastUser<Guid>.Email)] = new() { "Provided email already exists" };
                }
            }
            return errors;
        }

        public virtual bool VerifyPassword(TUser user, string password) => BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
    }
}
