using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FastJwtAuth.Abstractions.Services
{
    /// <summary>
    /// Service for managing Users
    /// </summary>
    /// <typeparam name="TUser">Type of User Entity</typeparam>
    /// <typeparam name="TRefreshToken">Type of RefreshToken Entity</typeparam>
    public interface IFastUserStore<TUser, TRefreshToken>
    {
        /// <summary>
        /// Validate User Entity
        /// </summary>
        /// <param name="user">User Entity to validate</param>
        /// <param name="password">Password to validate</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns>Dictionary of errors. Null if user is valid</returns>
        Task<Dictionary<string, List<string>>?> ValidateUserAsync(TUser user, string password, CancellationToken cancellationToken = default);
        
        /// <summary>
        /// Set datetimes for the user which should be set at creation time
        /// </summary>
        void SetCreationDateTimes(TUser user);

        /// <summary>
        /// Set datetimes for the user which should be set at creation time
        /// </summary>
        void SetLoginDateTimes(TUser user);

        /// <summary>
        /// Add User To Database
        /// </summary>
        /// <param name="user">User entity</param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task CreateUserAsync(TUser user, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets ExpireDate for RefreshToken
        /// </summary>
        /// <param name="refreshTokenEntity">RefreshToken entity</param>
        /// <returns>ExpireDate for RefreshToken</returns>
        DateTime GetRefreshTokenExpireDate(TRefreshToken refreshTokenEntity);

        /// <summary>
        /// Gets Identifier for RefreshToken. Identifier can be an Id or something that uniquely identifies the RefreshToken
        /// </summary>
        /// <param name="refreshTokenEntity">RefreshToken entity</param>
        /// <returns>RefreshToken identifier</returns>
        string GetRefreshTokenIdentifier(TRefreshToken refreshTokenEntity);

        /// <summary>
        /// Create RefreshToken
        /// </summary>
        /// <param name="user">User entity for refresh token</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns>Created RefreshToken</returns>
        Task<TRefreshToken> CreateRefreshTokenAsync(TUser? user, CancellationToken cancellationToken = default);


        /// <summary>
        /// Create claims for user
        /// </summary>
        IEnumerable<Claim> GetClaimsForUser(TUser user);

        /// <summary>
        /// Hash given password and set the hashed to User Entity
        /// </summary>
        /// <param name="user">User Entity</param>
        /// <param name="password">Unhashed text password</param>
        void SetPassword(TUser user, string password);
    }
}
