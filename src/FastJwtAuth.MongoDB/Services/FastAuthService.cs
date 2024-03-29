﻿namespace FastJwtAuth.MongoDB.Services;

using System.Buffers;
using System.Security.Cryptography;

[Open]
public class FastAuthService<TUser, TRefreshToken>
    : FastAuthServiceBase<TUser, TRefreshToken, string>, IFastAuthService<TUser, TRefreshToken>
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
{
    private readonly MongoFastAuthOptions<TUser, TRefreshToken> _mongoAuthOptions;
    private readonly IMongoDatabase _db;
    private readonly IMongoCollection<TUser> _usersCollection;
    private readonly IMongoCollection<TRefreshToken> _refreshTokenCollection;

    public FastAuthService(
        MongoFastAuthOptions<TUser, TRefreshToken> authOptions,
        IServiceProvider sp,
        IFastUserValidator<TUser>? userValidator = null)
        : base(authOptions, userValidator)
    {
        _mongoAuthOptions = authOptions;
        if (_mongoAuthOptions.MongoDatabaseGetter is not null)
        {
            _db = _mongoAuthOptions.MongoDatabaseGetter(sp);
            if (_db is null)
            {
                throw new NullReferenceException($"{nameof(authOptions.MongoDatabaseGetter)} should not return null");
            }
            _usersCollection = _db.GetCollection<TUser>(_mongoAuthOptions.UsersCollectionName);
            _refreshTokenCollection = _db.GetCollection<TRefreshToken>(_mongoAuthOptions.RefreshTokenCollectionName);
            return;
        }
        if (_mongoAuthOptions.MongoDbName is null)
        {
            throw new NullReferenceException($"{nameof(authOptions.MongoDbName)} should not be null if {nameof(authOptions.MongoDbName)}");
        }
        var mongoClient = (IMongoClient?)sp.GetService(typeof(IMongoClient));
        if (mongoClient is null)
        {
            throw new NullReferenceException($"{nameof(IMongoClient)} service is not added as service");
        }
        _db = mongoClient.GetDatabase(_mongoAuthOptions.MongoDbName);
        _usersCollection = _db.GetCollection<TUser>(_mongoAuthOptions.UsersCollectionName);
        _refreshTokenCollection = _db.GetCollection<TRefreshToken>(_mongoAuthOptions.RefreshTokenCollectionName);
    }

    protected override Task AddUser(TUser user, CancellationToken cancellationToken) =>
        _usersCollection.InsertOneAsync(user, null, cancellationToken);

    protected override async ValueTask<TRefreshToken> CreateRefreshToken(TUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken)
    {
        var randomBytes = ArrayPool<byte>.Shared.Rent(tokenCreationOptions.RefreshTokenBytesLength);

        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        var utcNow = DateTime.UtcNow;
        TRefreshToken refreshToken = new()
        {
            Id = Convert.ToBase64String(randomBytes),
            CreatedAt = utcNow,
            ExpiresAt = utcNow.Add(tokenCreationOptions.RefreshTokenLifeSpan),
            User = user
        };

        ArrayPool<byte>.Shared.Return(randomBytes);

        await _refreshTokenCollection.InsertOneAsync(refreshToken, null, cancellationToken);
        return refreshToken;
    }

    protected override Task<bool> NormalizedEmailExists(string normalizedEmail, CancellationToken cancellationToken)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastUser.NormalizedEmail)] = normalizedEmail
        };
        return _usersCollection.Find(filter).AnyAsync(cancellationToken);
    }

    protected override async Task<(TRefreshToken? RefreshToken, TUser? User)> GetRefreshTokenById(string id, CancellationToken cancellationToken)
    {
        var filter = new BsonDocument()
        {
            ["_id"] = id
        };
        var refreshToken = await _refreshTokenCollection.Find(filter)
            .FirstOrDefaultAsync(cancellationToken);
        return (refreshToken, refreshToken?.User);
    }

    protected override Task<TUser?> GetUserByNormalizedEmail(string normalizedEmail, CancellationToken cancellationToken)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastUser.NormalizedEmail)] = normalizedEmail
        };
        return _usersCollection.Find(filter).FirstOrDefaultAsync(cancellationToken)!;
    }

    protected override Task RemoveRefreshToken(TRefreshToken refreshTokenEntity, CancellationToken cancellationToken)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastRefreshToken.Id)] = refreshTokenEntity.Id
        };
        return _refreshTokenCollection.DeleteOneAsync(filter, cancellationToken);
    }

    protected override Task UpdateUserLastLogin(TUser user, CancellationToken cancellationToken)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastUser.Id)] = user.Id
        };
        var update = new BsonDocument()
        {
            [nameof(FastUser.LastLogin)] = user.LastLogin
        };
        return _usersCollection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken);
    }

    protected override Task CommitDbChanges(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    protected override Task<bool> NormalizedUsernameExists(string normalizedUsername, CancellationToken cancellationToken)
    {
        var filter = new BsonDocument()
        {
            [nameof(FastUser.NormalizedUsername)] = normalizedUsername
        };
        return _usersCollection.Find(filter).AnyAsync(cancellationToken);
    }

    public override TUser GetUser(ClaimsIdentity claimsIdentity)
    {
        TUser fastUser = new();
        foreach (var claim in claimsIdentity.Claims)
        {
            if (claim.Type == JwtRegisteredClaimNames.Email)
            {
                fastUser.Email = claim.Value;
                continue;
            }
            if (claim.Type == JwtRegisteredClaimNames.UniqueName)
            {
                fastUser.Username = claim.Value;
                continue;
            }
            if (claim.Type == JwtRegisteredClaimNames.Sub)
            {
                fastUser.Id = claim.Value;
                continue;
            }
            if (claim.Type == nameof(FastUser.CreatedAt))
            {
                fastUser.CreatedAt = DateTime.Parse(claim.Value);
                continue;
            }
        }
        return fastUser;
    }
}
