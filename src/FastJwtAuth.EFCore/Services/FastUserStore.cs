using FastJwtAuth.Core.Entities;
using FastJwtAuth.Core.Services;
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
    public class FastUserStore<TUser, TUserKey, TRefreshToken, TDbContext> : FastUserStoreCommons<TUser, TRefreshToken, TUserKey>
        where TUser : FastUser<TUserKey>, new()
        where TRefreshToken : FastRefreshToken<TUser, TUserKey>, new()
        where TDbContext : DbContext
    {
        protected readonly TDbContext _dbContext;

        public FastUserStore(TDbContext dbContext, FastAuthOptions authOptions)
            : base(authOptions)
        {
            _dbContext = dbContext;
        }

        protected override object getDbAccessor()
        {
            return _dbContext;
        }

        public override Task<bool> DoesNormalizedUserIdentifierExist(string nomalizeduserIdentifier, CancellationToken cancellationToken = default) => 
            _dbContext.Set<TUser>()
                .Where(user => user.NormalizedEmail == nomalizeduserIdentifier)
                .AnyAsync(cancellationToken);

        public override async Task<TRefreshToken> CreateRefreshTokenAsync(TUser? user, CancellationToken cancellationToken = default)
        {
            var randomBytes = new byte[_authOptions.RefreshTokenBytesLength];
            using var rng = new RNGCryptoServiceProvider();
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

        public override Task<TUser?> GetUserByNormalizedIdentifier(string normalizedUserIdentifier, CancellationToken cancellationToken = default) =>
            _dbContext.Set<TUser>()
                .Where(user => user.NormalizedEmail == normalizedUserIdentifier)
                .FirstOrDefaultAsync(cancellationToken)!;

        public override bool IsRefreshTokenUsed(TRefreshToken refreshTokenEntity)
        {
            return refreshTokenEntity is null;
        }

        public override Task MakeRefreshTokenUsedAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken = default)
        {
            _dbContext.Remove(refreshTokenEntity);
            return _dbContext.SaveChangesAsync(cancellationToken);
        }

        public override Task UpdateUserAsync(TUser user, CancellationToken cancellationToken = default)
        {
            _dbContext.Update(user);
            return _dbContext.SaveChangesAsync(cancellationToken);
        }
    }
}
