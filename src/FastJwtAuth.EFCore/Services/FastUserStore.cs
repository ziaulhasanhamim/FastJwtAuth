using FastJwtAuth.Core.Entities;
using FastJwtAuth.Core.Services;
using FastJwtAuth.EFCore.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FastJwtAuth.EFCore.Services
{
    public class FastUserStore<TUser, TRefreshToken, TDbContext> : FastUserStoreCommons<TUser, TRefreshToken, Guid>
        where TUser : FastUser, new()
        where TRefreshToken : FastRefreshToken<TUser>, new()
        where TDbContext : DbContext
    {
        private readonly TDbContext _dbContext;
        private readonly FastAuthOptions _authOptions;

        public FastUserStore(TDbContext dbContext, FastAuthOptions authOptions)
        {
            _dbContext = dbContext;
            _authOptions = authOptions;
        }

        public override async Task<TRefreshToken> CreateRefreshTokenAsync(TUser? user, CancellationToken cancellationToken = default)
        {
            var randomBytes = new byte[_authOptions.RefreshTokenBytesLength];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            TRefreshToken refreshToken = new()
            {
                Id = Convert.ToBase64String(randomBytes),
                ExpiresAt = DateTime.UtcNow.Add(_authOptions.AccessTokenLifeSpan),
                UserId = user!.Id
            };

            await _dbContext.AddAsync(refreshToken, cancellationToken);
            await _dbContext.SaveChangesAsync(cancellationToken);

            return refreshToken;
        }

        public override async Task CreateUserAsync(TUser user, CancellationToken cancellationToken = default)
        {
            await _dbContext.AddAsync(user, cancellationToken);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public override IEnumerable<Claim> GetClaimsForUser(TUser user)
        {
            List<Claim> claims = new()
            {
                new(JwtRegisteredClaimNames.Jti, user.Id!.ToString()!),
                new(JwtRegisteredClaimNames.Email, user.Email!),
                new(nameof(FastUser.CreatedAt), user.CreatedAt.ToString()!)
            };
            _authOptions.OnClaimsGeneration?.Invoke(claims, user);
            return claims;
        }

        public override async Task<(TRefreshToken? RefreshToken, TUser? User)> GetRefreshTokenByIdentifierAsync(string refreshTokenIdentifier, CancellationToken cancellationToken = default)
        {
            var refreshToken = await _dbContext.Set<TRefreshToken>()
                .Where(token => token.Id == refreshTokenIdentifier)
                .Include(token => token.User)
                .FirstOrDefaultAsync(cancellationToken);
            return (refreshToken, refreshToken?.User);
        }

        public override async Task<TUser?> GetUserByIdentifierAsync(string userIdentifier, CancellationToken cancellationToken = default)
        {
            return await _dbContext.Set<TUser>()
                .Where(user => user.Email == userIdentifier)
                .FirstOrDefaultAsync(cancellationToken);
        }

        public override bool IsRefreshTokenUsed(TRefreshToken refreshTokenEntity)
        {
            return refreshTokenEntity is null;
        }

        public override async Task MakeRefreshTokenUsedAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken = default)
        {
            _dbContext.Remove(refreshTokenEntity);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public override async Task UpdateUserAsync(TUser user, CancellationToken cancellationToken = default)
        {
            _dbContext.Update(user);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public override async Task<Dictionary<string, List<string>>?> ValidateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
        {
            Dictionary<string, List<string>>? errors = null;
            if (_authOptions.OnUserValidate is not null)
            {
                errors = await _authOptions.OnUserValidate(user, _dbContext);
            }
            
            var emailValidator = new EmailAddressAttribute();
            var emailValid = emailValidator.IsValid(user.Email);
            if (!emailValid)
            {
                if (errors is null)
                {
                    errors = new();
                }
                if (errors.TryGetValue(nameof(FastUser.Email), out var emailErrors))
                {
                    emailErrors.Add("Provided email is not valid");
                }
                errors[nameof(FastUser.Email)] = new() { "Provided email is not valid" };
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
            if (errors is null || !errors.ContainsKey(nameof(FastUser.Email)))
            {
                var emailExists = await _dbContext.Set<TUser>()
                    .Where(user2 => user2.Email == user.Email)
                    .AnyAsync(cancellationToken);
                if (emailExists)
                {
                    if (errors is null)
                    {
                        errors = new();
                    }
                    errors[nameof(FastUser.Email)] = new() { "Provided email already exists" };
                }
            }
            return errors;
        }
    }
}
