using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.MongoDB.Tests.Services
{
    public class MongoDBProvider : IAsyncDisposable
    {
        private readonly IMongoClient _mongoClient;

        private bool _isDisposed;

        public IMongoDatabase TestDatabase { get; private set; }

        public MongoDBProvider(string connectionStr = "mongodb://127.0.0.1:27017/")
        {
            _mongoClient = new MongoClient(connectionStr);
            TestDatabase = _mongoClient.GetDatabase($"{Guid.NewGuid()}--FastJwtAuthTestDb");
        }

        public async ValueTask DisposeAsync()
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException("Already disposed provider");
            }
            await _mongoClient.DropDatabaseAsync(TestDatabase.DatabaseNamespace.DatabaseName);
        }
    }
}
