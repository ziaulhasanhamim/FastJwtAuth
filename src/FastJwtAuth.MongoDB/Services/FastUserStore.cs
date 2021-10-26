namespace FastJwtAuth.MongoDB.Services;

using System.Security.Cryptography;


public class FastUserStore<TUser, TRefreshToken> : FastUserStoreCommons<TUser, TRefreshToken, string>
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
{
    private readonly MongoFastAuthOptions _mongoAuthOptions;
    private readonly IMongoDatabase _db;
    private readonly IMongoCollection<TUser> _usersCollection;
    private readonly IMongoCollection<TRefreshToken> _refreshTokenCollection;

    public FastUserStore(MongoFastAuthOptions authOptions, IServiceProvider sp, IFastUserValidator<TUser>? userValidator = null)
        : base(authOptions, userValidator)
    {
        _mongoAuthOptions = authOptions;
        if (_mongoAuthOptions.MongoDatabaseGetter is not null)
        {
            _db = _mongoAuthOptions.MongoDatabaseGetter(sp);
            if (_db is null)
            {
                throw new NullReferenceException($"{nameof(MongoFastAuthOptions.MongoDatabaseGetter)} should not return null");
            }
            _usersCollection = _db.GetCollection<TUser>("FastUsers");
            _refreshTokenCollection = _db.GetCollection<TRefreshToken>("FastRefreshTokens");
            return;
        }
        if (_mongoAuthOptions.MongoDbName is null)
        {
            throw new NullReferenceException($"{nameof(MongoFastAuthOptions.MongoDbName)} should not be null if {nameof(MongoFastAuthOptions.MongoDbName)}");
        }
        var mongoClient = (IMongoClient?)sp.GetService(typeof(IMongoClient));
        if (mongoClient is null)
        {
            throw new NullReferenceException($"{nameof(IMongoClient)} service is not added as service");
        }
        _db = mongoClient.GetDatabase(_mongoAuthOptions.MongoDbName);
        _usersCollection = _db.GetCollection<TUser>("FastUsers");
        _refreshTokenCollection = _db.GetCollection<TRefreshToken>("FastRefreshTokens");
    }

    public override async Task<TRefreshToken> CreateRefreshTokenAsync(TUser user, CancellationToken cancellationToken = default)
    {
        var randomBytes = new byte[_mongoAuthOptions.RefreshTokenBytesLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        TRefreshToken refreshToken = new()
        {
            Id = Convert.ToBase64String(randomBytes),
            ExpiresAt = DateTime.UtcNow.Add(_mongoAuthOptions.RefreshTokenLifeSpan),
            User = user
        };

        await _refreshTokenCollection.InsertOneAsync(refreshToken, null, cancellationToken);
        return refreshToken;
    }

    public override Task CreateUserAsync(TUser user, CancellationToken cancellationToken = default) =>
        _usersCollection.InsertOneAsync(user, null, cancellationToken);

    public override Task<bool> DoesNormalizedUserIdentifierExistAsync(string nomalizeduserIdentifier, CancellationToken cancellationToken = default)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastUser.NormalizedEmail)] = nomalizeduserIdentifier
        };
        return _usersCollection.Find(filter).AnyAsync(cancellationToken);
    }

    public override async Task<(TRefreshToken? RefreshToken, TUser? User)> GetRefreshTokenByIdentifierAsync(string refreshTokenIdentifier, CancellationToken cancellationToken = default)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastRefreshToken.Id)] = refreshTokenIdentifier
        };
        var refreshToken = await _refreshTokenCollection.Find(filter)
            .FirstOrDefaultAsync(cancellationToken);
        return (refreshToken, refreshToken?.User);
    }

    public override Task<TUser?> GetUserByNormalizedIdentifierAsync(string normalizedUserIdentifier, CancellationToken cancellationToken = default)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastUser.NormalizedEmail)] = normalizedUserIdentifier
        };
        return _usersCollection.Find(filter).FirstOrDefaultAsync(cancellationToken)!;
    }

    public override Task MakeRefreshTokenUsedAsync(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken = default)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastRefreshToken.Id)] = refreshTokenEntity.Id
        };
        return _refreshTokenCollection.DeleteOneAsync(filter, cancellationToken);
    }

    public override Task UpdateUserAsync(TUser user, CancellationToken cancellationToken = default)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastUser.Id)] = user.Id
        };
        return _usersCollection.ReplaceOneAsync(filter, user, cancellationToken: cancellationToken);
    }
}
