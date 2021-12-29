namespace FastJwtAuth.MongoDB.Tests.Services;

using FastJwtAuth.MongoDB.Services;
using FastJwtAuth.MongoDB.Tests.AutofixtureUtils;
using FluentAssertions;
using global::MongoDB.Driver;
using NSubstitute;
using Xunit;

public class FastUserStoreTests
{
    [Theory, MoreAutoData]
    public async Task ValidateUserAsync_InvalidEmailAndPassword_CustomErrors_ErrorsReturned(
        FastUser user,
        MongoFastAuthOptions authOptions)
    {
        user.Email = "test";
        var password = "test";
        TestUserValidator userValidator = new((_, _) =>
        {
            return (false, new() { "OtherErrorCode" });
        });

        authOptions.MongoDatabaseGetter = _ => Substitute.For<IMongoDatabase>();

        FastUserStore<FastUser, FastRefreshToken> userStore = new(authOptions, null!, userValidator);

        var result = await userStore.ValidateUserAsync(user, password);

        result.Should().NotBeNull();
        result.Should().HaveCount(3);
        result.Should().Contain(FastAuthErrorCodes.InvalidEmailFormat);
        result.Should().Contain(FastAuthErrorCodes.PasswordVeryShort);
        result.Should().Contain("OtherErrorCode");
    }

    [Theory, MoreAutoData]
    public async Task ValidateUserAsync_DuplicateEmailAndPassword_CustomErrors_ErrorsReturned(
        FastUser user,
        MongoFastAuthOptions authOptions)
    {
        user.Email = "test@test.com";
        user.NormalizedEmail = user.Email.Normalize().ToUpperInvariant();
        user.Id = null;
        var password = "test";
        TestUserValidator userValidator = new((_, _) =>
        {
            return (false, new() { "OtherErrorCode" });
        });

        await using MongoDBProvider dbProvider = new();
        authOptions.MongoDatabaseGetter = _ => dbProvider.TestDatabase;

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

    [Theory, MoreAutoData]
    public async Task ValidateUserAsync_AllOkay_NullReturned(MongoFastAuthOptions authOptions)
    {
        FastUser user = new()
        {
            Email = "test@test.com",
            NormalizedEmail = "test@test.com".Normalize().ToUpperInvariant()
        };
        var password = "test1234";

        await using MongoDBProvider dbProvider = new();

        authOptions.MongoDatabaseGetter = _ => dbProvider.TestDatabase;
        FastUserStore<FastUser, FastRefreshToken> userStore = new(authOptions, null!);

        var result = await userStore.ValidateUserAsync(user, password);

        result.Should().BeNull();
    }
}
