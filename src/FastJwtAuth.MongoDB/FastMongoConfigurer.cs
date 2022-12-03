using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;

namespace FastJwtAuth.MongoDB;

public static class FastMongoConfigurer
{
    public static async Task Configure<TUser, TRefreshToken>(
        IMongoCollection<TUser> usersCollection,
        IMongoCollection<TRefreshToken> refreshTokensCollection,
        MongoFastAuthOptions<TUser, TRefreshToken> authOptions)
        where TUser : FastUser, new()
        where TRefreshToken : FastRefreshToken<TUser>, new()
    {
        BsonClassMap.RegisterClassMap<TUser>(cm =>
        {
            cm.AutoMap();
            cm.MapIdMember(user => user.Id)
                .SetSerializer(new StringSerializer(BsonType.ObjectId));
            if (authOptions.UsernameState is FastFieldState.Nope)
            {
                cm.UnmapMember(user => user.Username);
                cm.UnmapMember(user => user.NormalizedUsername);
            }
            if (authOptions.EmailState is FastFieldState.Nope)
            {
                cm.UnmapMember(user => user.Email);
                cm.UnmapMember(user => user.NormalizedEmail);
            }
        });

        BsonClassMap.RegisterClassMap<TRefreshToken>(cm =>
        {
            cm.AutoMap();
            cm.MapIdMember(user => user.Id)
                .SetSerializer(new StringSerializer(BsonType.ObjectId));
        });
        List<CreateIndexModel<TUser>> indexes = new();

        if (authOptions.EmailState is not FastFieldState.Nope)
        {
            var mailIndexKeysDefinition = Builders<TUser>.IndexKeys
                .Ascending(user => user.NormalizedEmail);
            indexes.Add(new(mailIndexKeysDefinition));
        }

        if (authOptions.UsernameState is not FastFieldState.Nope)
        {
            var usernameNormalizedIndexKeysDefinition = Builders<TUser>.IndexKeys
                .Ascending(user => user.NormalizedUsername);
            indexes.Add(new(usernameNormalizedIndexKeysDefinition));
        }
        await usersCollection.Indexes.CreateManyAsync(indexes);
    }

    public static Task Configure<TUser, TRefreshToken>(
        IMongoDatabase _db,
        MongoFastAuthOptions<TUser, TRefreshToken> authOptions)
        where TUser : FastUser, new()
        where TRefreshToken : FastRefreshToken<TUser>, new()
    {
        return Configure(
            _db.GetCollection<TUser>(authOptions.UsersCollectionName),
            _db.GetCollection<TRefreshToken>(authOptions.RefreshTokenCollectionName),
            authOptions);
    }

    public static Task Configure<TUser>(
        IMongoDatabase _db,
        MongoFastAuthOptions<TUser> authOptions)
        where TUser : FastUser, new()
    {
        return Configure<TUser, FastRefreshToken<TUser>>(_db, authOptions);
    }

    public static Task Configure(
        IMongoDatabase _db,
        MongoFastAuthOptions authOptions)
    {
        return Configure<FastUser, FastRefreshToken>(_db, authOptions);
    }
}