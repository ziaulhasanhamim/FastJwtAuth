namespace FastJwtAuth.MongoDB.Tests.Services;

using global::MongoDB.Bson;
using global::MongoDB.Driver;
using Microsoft.Extensions.Configuration;
using System;
using System.Threading.Tasks;


public class MongoDBProvider : IAsyncDisposable
{
    private static IConfiguration _configurations = 
        new ConfigurationBuilder()
            .AddUserSecrets<MongoDBProvider>(true)
            .Build();

    private readonly IMongoClient _mongoClient;

    private bool _isDisposed;

    public IMongoDatabase TestDatabase { get; private set; }

    public MongoDBProvider()
    {
        var connectionStr = _configurations["mongo-testdb-connection"] ?? "mongodb://127.0.0.1:27017/";
        var dbName = _configurations["mongo-testdb-name"] ?? "FastJwtAuthTestDb";
        _mongoClient = new MongoClient(connectionStr);
        TestDatabase = _mongoClient.GetDatabase(dbName);
    }

    public async ValueTask DisposeAsync()
    {
        if (_isDisposed)
        {
            throw new ObjectDisposedException("Already disposed provider");
        }
        _isDisposed = true;
        await _mongoClient.DropDatabaseAsync(TestDatabase.DatabaseNamespace.DatabaseName);
    }
}
