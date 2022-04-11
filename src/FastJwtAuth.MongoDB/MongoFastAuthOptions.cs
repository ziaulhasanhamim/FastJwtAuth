namespace FastJwtAuth.MongoDB;

public class MongoFastAuthOptions<TUser, TRefreshToken> : FastAuthOptions<TUser, TRefreshToken, string>
    where TUser : FastUser
    where TRefreshToken : FastRefreshToken<TUser>
{
    public string? MongoDbName { get; set; }

    /// <summary>
    /// Default to "FastUsers"
    /// </summary>
    public string UsersCollectionName { get; set; } = "FastUsers";

    /// <summary>
    /// Default to "FastRefreshTokens"
    /// </summary>
    public string RefreshTokenCollectionName { get; set; } = "FastRefreshTokens";

    public Func<IServiceProvider, IMongoDatabase>? MongoDatabaseGetter { get; set; }
}

public class MongoFastAuthOptions<TUser> : MongoFastAuthOptions<TUser, FastRefreshToken<TUser>>
    where TUser : FastUser
{
    
}

public class MongoFastAuthOptions : MongoFastAuthOptions<FastUser, FastRefreshToken>
{
    
}