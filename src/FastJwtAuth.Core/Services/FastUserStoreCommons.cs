using FastJwtAuth.Core.Entities;
using FastJwtAuth;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace FastJwtAuth.Core.Services
{
    public abstract class FastUserStoreCommons<TUser, TRefreshToken, TKey> : IFastUserStore<TUser, TRefreshToken>
        where TUser : class, IFastUser<TKey>
        where TRefreshToken : class, IRefreshToken<TKey>
    {
        public abstract Task<TRefreshToken> CreateRefreshTokenAsync(TUser? user, CancellationToken cancellationToken = default);

        public abstract Task CreateUserAsync(TUser user, CancellationToken cancellationToken = default);

        public abstract IEnumerable<Claim> GetClaimsForUser(TUser user);

        public abstract Task<(TRefreshToken? refreshToken, TUser? user)> GetRefreshTokenByIdentifierAsync(string refreshTokenIdentifier, CancellationToken cancellationToken = default);

        public DateTime GetRefreshTokenExpireDate(TRefreshToken refreshTokenEntity) => refreshTokenEntity.ExpiresAt;

        public string GetRefreshTokenIdentifier(TRefreshToken refreshTokenEntity) => refreshTokenEntity.Id!;

        public abstract Task<TUser?> GetUserByIdentifierAsync(string userIdentifier, CancellationToken cancellationToken = default);

        public bool IsRefreshTokenExpired(TRefreshToken refreshTokenEntity) => refreshTokenEntity.ExpiresAt < DateTime.UtcNow;

        public abstract bool IsRefreshTokenUsed(TRefreshToken refreshTokenEntity);
        public abstract Task MakeRefreshTokenUsedAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken = default);

        public void SetCreationDateTimes(TUser user) => user.CreatedAt = DateTime.UtcNow;

        public void SetLoginDateTimes(TUser user) => user.LastLogin = DateTime.UtcNow;

        public void SetPassword(TUser user, string password) => user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(password);

        public abstract Task UpdateUserAsync(TUser user, CancellationToken cancellationToken = default);

        public abstract Task<Dictionary<string, List<string>>?> ValidateUserAsync(TUser user, string password, CancellationToken cancellationToken = default);

        public bool VerifyPassword(TUser user, string password) => BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
    }
}
