namespace FastJwtAuth;

using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

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
    /// <param name="validateUser">Specify that if user needs to be validated before creation</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns><see cref="SuccessAuthResult{TUser}"/> if creation was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
    Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, bool validateUser, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new User
    /// </summary>
    /// <param name="user">The user entity</param>
    /// <param name="password">Password for the user</param>
    /// <param name="validateUser">Specify that if user needs to be validated before creation</param>
    /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns><see cref="SuccessAuthResult{TUser}"/> if creation was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
    Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, bool validateUser, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default);

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
    /// <returns><see cref="SuccessAuthResult{TUser}"/> if refresh was successful else returns <see cref="FailureAuthResult{TUser}"/></returns>
    Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validate User Entity
    /// </summary>
    /// <param name="user">User Entity to validate</param>
    /// <param name="password">Password to validate</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns>Dictionary of errors. Null if user is valid</returns>
    ValueTask<Dictionary<string, List<string>>?> ValidateUserAsync(TUser user, string password, CancellationToken cancellationToken = default);
}
