namespace FastJwtAuth.MongoDB;

using Microsoft.Extensions.Hosting;


public class MongoStartupService<TUser, TRefreshToken> : IHostedService
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
{
    private readonly IMongoDatabase _db;

    public MongoStartupService(MongoFastAuthOptions authOptions, IServiceProvider sp)
    {
        if (authOptions.MongoDatabaseGetter is not null)
        {
            _db = authOptions.MongoDatabaseGetter(sp);
            if (_db is null)
            {
                throw new NullReferenceException($"{nameof(MongoFastAuthOptions.MongoDatabaseGetter)} should not return null");
            }
            return;
        }
        if (authOptions.MongoDbName is null)
        {
            throw new NullReferenceException($"{nameof(MongoFastAuthOptions.MongoDbName)} should not be null if {nameof(MongoFastAuthOptions.MongoDbName)}");
        }
        var mongoClient = (IMongoClient?)sp.GetService(typeof(IMongoClient));
        if (mongoClient is null)
        {
            throw new NullReferenceException($"{nameof(IMongoClient)} service is not added as service");
        }
        _db = mongoClient.GetDatabase(authOptions.MongoDbName);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        return _db.CreateFastAuthDBIndexes<TUser>();
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
