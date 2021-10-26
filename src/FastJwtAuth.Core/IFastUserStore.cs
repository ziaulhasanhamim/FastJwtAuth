namespace FastJwtAuth;

/// <summary>
/// Service for managing Users
/// </summary>
/// <typeparam name="TUser">Type of User Entity</typeparam>
/// <typeparam name="TRefreshToken">Type of RefreshToken Entity</typeparam>
public interface IFastUserStore<TUser, TRefreshToken>
    where TUser : class
    where TRefreshToken : class
{
    /// <summary>
    /// Validate User Entity
    /// </summary>
    /// <param name="user">User Entity to validate</param>
    /// <param name="password">Password to validate</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns>Dictionary of errors. Null if user is valid</returns>
    ValueTask<Dictionary<string, List<string>>?> ValidateUserAsync(TUser user, string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Set datetimes for the user which should be set at creation time
    /// </summary>
    void SetCreationDateTimes(TUser user);

    /// <summary>
    /// Set datetimes for the user which should be set at creation time
    /// </summary>
    void SetLoginDateTimes(TUser user);

    /// <summary>
    /// Set the normalized fields like email and username
    /// </summary>
    void SetNormalizedFields(TUser user);

    /// <summary>
    /// Add User To Database
    /// </summary>
    /// <param name="user">User entity</param>
    /// <param name="cancellationToken"></param>
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
    Task<TRefreshToken> CreateRefreshTokenAsync(TUser user, CancellationToken cancellationToken = default);


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

    /// <summary>
    /// Update user entity on db
    /// </summary>
    Task UpdateUserAsync(TUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Check if Refresh token expired
    /// </summary>
    bool IsRefreshTokenExpired(TRefreshToken refreshTokenEntity);

    /// <summary>
    /// Gets referesh token and user by identifier 
    /// </summary>
    /// <param name="refreshTokenIdentifier">Referesh token identifier</param>
    /// <param name="cancellationToken">This can be used to cancel the operation</param>
    /// <returns>A tuple containing user and tuple</returns>
    Task<(TRefreshToken? RefreshToken, TUser? User)> GetRefreshTokenByIdentifierAsync(string refreshTokenIdentifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get User from db by identifier. it will first normalize the identifier
    /// </summary>
    /// <param name="userIdentifier">Identifier for user such as email or username</param>
    /// <returns>User Entity or null if not found</returns>
    Task<TUser?> GetUserByIdentifierAsync(string userIdentifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get User from db by normalized identifier. You have to provide normalized identifier
    /// </summary>
    /// <param name="normalizedUserIdentifier">Identifier for user such as email or username</param>
    /// <returns>User Entity or null if not found</returns>
    Task<TUser?> GetUserByNormalizedIdentifierAsync(string normalizedUserIdentifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verify password with the user's password
    /// </summary>
    /// <param name="user">User Entity</param>
    /// <param name="password">Unhashed text password</param>
    /// <returns>true if password was right</returns>
    bool VerifyPassword(TUser user, string password);

    /// <summary>
    /// Make the refresh token used. so that it cant be used anymore
    /// </summary>
    Task MakeRefreshTokenUsedAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Check if user identifier exists. it will first normalize identifier
    /// </summary>
    Task<bool> DoesUserIdentifierExist(string userIdentifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Check if user identifier exists. You have to provide normalized identifier
    /// </summary>
    Task<bool> DoesNormalizedUserIdentifierExistAsync(string nomalizeduserIdentifier, CancellationToken cancellationToken = default);

    string NormalizeUserIdentifier(string identifier);
}
