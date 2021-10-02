using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FastJwtAuth
{
    /// <summary>
    /// Service for managing Authentication And Authorization
    /// </summary>
    /// <typeparam name="TUser">Type of User Entity</typeparam>
    /// <typeparam name="TRefreshToken">Type of RefreshToken Entity</typeparam>
    public interface IFastAuthService<TUser, TRefreshToken>
        where TUser : class
        where TRefreshToken : class
    {
        /// <summary>
        /// Creates a new User
        /// </summary>
        /// <param name="user">The user entity</param>
        /// <param name="password">Password for the user</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if creation was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new User
        /// </summary>
        /// <param name="user">The user entity</param>
        /// <param name="password">Password for the user</param>
        /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
        /// <param name="beforeCreate">This will be invoked before adding the user to db</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if creation was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, SigningCredentials? signingCredentials, Action<TUser>? beforeCreate, CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a new User
        /// </summary>
        /// <param name="user">The user entity</param>
        /// <param name="password">Password for the user</param>
        /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if creation was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default);

        /// <summary>
        /// Login an user
        /// </summary>
        /// <param name="userIdentifier">Identifier for user such as email or username</param>
        /// <param name="password">Password for the user</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if login was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> LoginUserAsync(string userIdentifier, string password, CancellationToken cancellationToken = default);

        /// <summary>
        /// Login an user
        /// </summary>
        /// <param name="userIdentifier">Identifier for user such as email or username</param>
        /// <param name="password">Password for the user</param>
        /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
        /// <param name="beforeLogin">This will be invoked before adding the user to db</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if login was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> LoginUserAsync(string userIdentifier, string password, SigningCredentials? signingCredentials, Action<TUser>? beforeLogin, CancellationToken cancellationToken = default);
        
        /// <summary>
        /// Login an user
        /// </summary>
        /// <param name="userIdentifier">Identifier for user such as email or username</param>
        /// <param name="password">Password for the user</param>
        /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if login was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> LoginUserAsync(string userIdentifier, string password, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default);

        /// <summary>
        /// Refresh and gets new a refresh token and access token
        /// </summary>
        /// <param name="refreshToken">The user entity</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if refresh was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);

        /// <summary>
        /// Refresh and gets new a refresh token and access token
        /// </summary>
        /// <param name="refreshToken">The user entity</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
        /// <param name="beforeRefresh">This will be invoked before adding the user to db</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if refresh was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, SigningCredentials? signingCredentials, Action<TUser>? beforeRefresh, CancellationToken cancellationToken = default);
        
        /// <summary>
        /// Refresh and gets new a refresh token and access token
        /// </summary>
        /// <param name="refreshToken">The user entity</param>
        /// <param name="cancellationToken">This can be used to cancel the operation</param>
        /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
        /// <returns><see cref="SuccessAuthResult{TUser}"/> if refresh was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
        Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default);
    }
}
