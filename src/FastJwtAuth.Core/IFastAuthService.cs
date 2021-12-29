namespace FastJwtAuth;

using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Service for managing Authentication And Authorization
/// </summary>
/// <typeparam name="TUser">Type of User Entity</typeparam>
/// <typeparam name="TRefreshToken">Type of RefreshToken Entity</typeparam>
/// <typeparam name="TUserKey">Type of User Key</typeparam>
public interface IFastAuthService<TUser, TRefreshToken, TUserKey>
    where TUser : class, IFastUser<TUserKey>, new()
    where TRefreshToken : class, IFastRefreshToken<TUserKey>, new()
{
    /// <summary>
    /// Create a new User
    /// </summary>
    /// <param name="user">The user entity</param>
    /// <param name="password">Password for the user</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns><see cref="CreateUserResult"/> containing error codes if there is any error</returns>
    Task<CreateUserResult> CreateUserAsync(TUser user, string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates an user user
    /// </summary>
    /// <param name="email">Email of user</param>
    /// <param name="password">Password of user</param>
    /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns><see cref="AuthResult{TUser}.Success"/> if login was successful else returns <see cref="AuthResult{TUser}.Failure"/></returns>
    Task<AuthResult<TUser>> AuthenticateAsync(string email, string password, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates an user user
    /// </summary>
    /// <param name="email">Email of user</param>
    /// <param name="password">Password of user</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns><see cref="AuthResult{TUser}.Success"/> if login was successful else returns <see cref="AuthResult{TUser}.Failure"/></returns>
    Task<AuthResult<TUser>> AuthenticateAsync(string email, string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates an user user
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    Task<AuthResult<TUser>.Success> AuthenticateAsync(TUser user, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates an user user
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    Task<AuthResult<TUser>.Success> AuthenticateAsync(TUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refresh and get new a refresh token and access token
    /// </summary>
    /// <param name="refreshToken">The user entity</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns><see cref="AuthResult{TUser}.Success"/> if refresh was successful else returns <see cref="AuthResult{TUser}.Failure"/></returns>
    Task<AuthResult<TUser>> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refresh and get new a refresh token and access token
    /// </summary>
    /// <param name="refreshToken">The user entity</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <param name="signingCredentials">SigningCredentials for jwt signing it will be used. If none default one will be used from FastAuthOptions</param>
    /// <returns><see cref="AuthResult{TUser}.Success"/> if refresh was successful else returns <see cref="AuthResult{TUser}.Failure"/></returns>
    Task<AuthResult<TUser>> RefreshAsync(string refreshToken, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default);

    string HashPassword(string password);

    bool VerifyPassword(string rawPassword, string hashedPassword);

    string NormalizeEmail(string email);
}
