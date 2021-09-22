using FastJwtAuth.Abstractions.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FastJwtAuth.Abstractions.Services
{
    /// <summary>
    /// Service for managing Authentication And Authorization
    /// </summary>
    /// <typeparam name="TUser">Type of User Entity</typeparam>
    /// <typeparam name="TRefreshToken">Type of RefreshToken Entity</typeparam>
    public interface IFastAuthService<TUser, TRefreshToken>
    {
        /// <summary>
        /// Creates a new User
        /// </summary>
        /// <param name="user">The user entity</param>
        /// <param name="password">Password for the user</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult"/> if creation was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, CancellationToken cancellationToken = default);

        /// <summary>
        /// Login an user
        /// </summary>
        /// <param name="loginIdentifier">Identifier for user such as email or username</param>
        /// <param name="password">Password for the user</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if login was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> LoginUserAsync(string loginIdentifier, string password, CancellationToken cancellationToken = default);

        /// <summary>
        /// Refresh and gets new a refresh token and access token
        /// </summary>
        /// <param name="refreshToken">The user entity</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if refresh was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);
    }
}
