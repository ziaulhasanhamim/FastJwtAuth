namespace FastJwtAuth.MongoDB;

public class MongoFastAuthOptions : FastAuthOptions
{
    public string? MongoDbName { get; set; }

    public Func<IServiceProvider, IMongoDatabase>? MongoDatabaseGetter { get; set; }
}
