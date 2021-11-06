namespace FastJwtAuth.MongoDB;

using Microsoft.Extensions.Hosting;


public class MongoStartupService<TUser, TRefreshToken> : IHostedService
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
{
    private IMongoCollection<TUser> _usersCollection;

    public MongoStartupService(MongoFastAuthOptions authOptions, IServiceProvider sp)
    {
        IMongoDatabase db;
        if (authOptions.MongoDatabaseGetter is not null)
        {
            db = authOptions.MongoDatabaseGetter(sp);
            if (db is null)
            {
                throw new NullReferenceException($"{nameof(MongoFastAuthOptions.MongoDatabaseGetter)} should not return null");
            }
            _usersCollection = db.GetCollection<TUser>(authOptions.UsersCollectionName);
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
        db = mongoClient.GetDatabase(authOptions.MongoDbName);
        _usersCollection = db.GetCollection<TUser>(authOptions.UsersCollectionName);
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await _usersCollection.CreateFastUserIndexes();
        _usersCollection = null!;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
