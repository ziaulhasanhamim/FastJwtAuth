namespace FastJwtAuth.MongoDB.Tests.Services;

using FastJwtAuth.MongoDB.Services;
using FluentAssertions;
using global::MongoDB.Driver;
using NSubstitute;
using Xunit;

public class FastUserStoreTests
{
    [Fact]
    public async Task ValidateUserAsync_InvalidEmailAndPassword_CustomErrors_ErrorsReturned()
    {
        FastUser user = new()
        {
            Email = "test",
            NormalizedEmail = "test".Normalize().ToUpperInvariant()
        };
        var password = "test";
        TestUserValidator userValidator = new((_, _) =>
        {
            return (false, new() { "OtherErrorCode" });
        });
        MongoFastAuthOptions<FastUser, FastRefreshToken> authOptions = new()
        {
            MongoDatabaseGetter = _ => Substitute.For<IMongoDatabase>()
        };

        FastUserStore<FastUser, FastRefreshToken> userStore = new(authOptions, null!, userValidator);

        var result = await userStore.ValidateUserAsync(user, password);

        result.Should().NotBeNull();
        result.Should().HaveCount(3);
        result.Should().Contain(FastAuthErrorCodes.InvalidEmailFormat);
        result.Should().Contain(FastAuthErrorCodes.PasswordVeryShort);
        result.Should().Contain("OtherErrorCode");
    }

    [Fact]
    public async Task ValidateUserAsync_DuplicateEmail_CustomErrors_ErrorsReturned()
    {
        FastUser user = new()
        {
            Email = "test@test.com",
            NormalizedEmail = "test@test.com".Normalize().ToUpperInvariant()
        };
        var password = "test";
        TestUserValidator userValidator = new((_, _) =>
        {
            return (false, new() { "OtherErrorCode" });
        });

        await using MongoDBProvider dbProvider = new();
        
        MongoFastAuthOptions<FastUser, FastRefreshToken> authOptions = new()
        {
            MongoDatabaseGetter = _ => dbProvider.TestDatabase
        };

        var usersCollections = dbProvider.TestDatabase
            .GetCollection<FastUser>(authOptions.UsersCollectionName);
        await usersCollections.InsertOneAsync(user);

        FastUserStore<FastUser, FastRefreshToken> userStore = new(authOptions, null!, userValidator);

        var result = await userStore.ValidateUserAsync(user, password);

        result.Should().NotBeNull();
        result.Should().HaveCount(3);
        result.Should().Contain(FastAuthErrorCodes.DuplicateEmail);
        result.Should().Contain(FastAuthErrorCodes.PasswordVeryShort);
        result.Should().Contain("OtherErrorCode");
    }

    [Fact]
    public async Task ValidateUserAsync_AllOkay_NullReturned()
    {
        FastUser user = new()
        {
            Email = "test@test.com",
            NormalizedEmail = "test@test.com".Normalize().ToUpperInvariant()
        };
        var password = "test1234";

        await using MongoDBProvider dbProvider = new();
        MongoFastAuthOptions authOptions = new()
        {
            MongoDatabaseGetter = _ => dbProvider.TestDatabase
        };
        FastUserStore<FastUser, FastRefreshToken> userStore = new(authOptions, null!);

        var result = await userStore.ValidateUserAsync(user, password);

        result.Should().BeNull();
    }
}
