namespace FastJwtAuth.MongoDB;

public class MongoFastAuthOptions : FastAuthOptions
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
