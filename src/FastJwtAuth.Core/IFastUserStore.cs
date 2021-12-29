namespace FastJwtAuth;

/// <summary>
/// Service for managing Users
/// </summary>
/// <typeparam name="TUser">Type of User Entity</typeparam>
/// <typeparam name="TRefreshToken">Type of RefreshToken Entity</typeparam>
/// <typeparam name="TUserKey">Type of User Key</typeparam>
public interface IFastUserStore<TUser, TRefreshToken, TUserKey>
    where TUser : class, IFastUser<TUserKey>, new()
    where TRefreshToken : class, IFastRefreshToken<TUserKey>, new()
{
    /// <summary>
    /// Validate User Entity
    /// </summary>
    /// <param name="user">User Entity to validate</param>
    /// <param name="password">Password to validate</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns>List of errors. Null if user is valid</returns>
    ValueTask<List<string>?> ValidateUserAsync(TUser user, string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Add User To Database
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="cancellationToken"></param>
    Task CreateUserAsync(TUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Create RefreshToken
    /// </summary>
    /// <param name="user">User entity for refresh token</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns>Created RefreshToken</returns>
    Task<TRefreshToken> CreateRefreshTokenAsync(TUser user, CancellationToken cancellationToken = default);


    /// <summary>
    /// Create claims for user
    /// </summary>
    IEnumerable<Claim> GetClaimsForUser(TUser user);

    /// <summary>
    /// Hash given password and set the hashed to User Entity
    /// </summary>
    /// <param name="password">Unhashed text password</param>
    /// <returns>Hashed password</returns>
    string HashPassword(string password);

    /// <summary>
    /// Update user entity on db
    /// </summary>
    Task UpdateUserAsync(TUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets referesh token and user by identifier 
    /// </summary>
    /// <param name="id">Referesh token identifier</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns>A tuple containing user and tuple</returns>
    Task<(TRefreshToken? RefreshToken, TUser? User)> GetRefreshTokenByIdAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get User from db by identifier. it will first normalize the identifier
    /// </summary>
    /// <param name="email">Identifier for user such as email or username</param>
    /// <returns>User Entity or null if not found</returns>
    Task<TUser?> GetUserByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get User from db by normalized identifier. You have to provide normalized identifier
    /// </summary>
    /// <param name="normalizedEmail">Identifier for user such as email or username</param>
    /// <returns>User Entity or null if not found</returns>
    Task<TUser?> GetUserByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verify password with the user's password
    /// </summary>
    /// <param name="rawPassword">Unhashed text password</param>
    /// <param name="hashedPassword">Hashed password</param>
    /// <returns>true if password was right</returns>
    bool VerifyPassword(string rawPassword, string hashedPassword);

    /// <summary>
    /// Make the refresh token used. so that it cant be used anymore
    /// </summary>
    Task RemoveRefreshTokenAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Check if emnail exists. it will first normalize identifier
    /// </summary>
    Task<bool> DoesEmailExist(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Check if emnail exists. You have to provide normalized identifier
    /// </summary>
    Task<bool> DoesNormalizedEmailExistAsync(string normalizedEmail, CancellationToken cancellationToken = default);

    string NormalizeEmail(string email);
}
