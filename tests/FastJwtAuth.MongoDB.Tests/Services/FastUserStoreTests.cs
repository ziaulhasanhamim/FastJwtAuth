using AutoFixture.Xunit2;
using FastJwtAuth.MongoDB.Services;
using FastJwtAuth.MongoDB.Tests.AutofixtureUtils;
using FluentAssertions;
using MongoDB.Driver;
using NSubstitute;
using NSubstitute.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace FastJwtAuth.MongoDB.Tests.Services
{
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
                Dictionary<string, List<string>> errors = new()
                {
                    ["TestField"] = new() { "Some Error" }
                };
                return (false, errors)!;
            });

            authOptions.MongoDatabaseGetter = _ => Substitute.For<IMongoDatabase>();

            FastUserStore<FastUser, FastRefreshToken> userStore = new(authOptions, null!, userValidator);

            var result = await userStore.ValidateUserAsync(user, password);

            result.Should().NotBeNull();
            result.Should().HaveCount(3);
            result!.ContainsKey(nameof(FastUser.Email)).Should().BeTrue();
            result!.ContainsKey("Password").Should().BeTrue();
            result!.ContainsKey("TestField").Should().BeTrue();
        }

        [Theory, MoreAutoData]
        public async Task ValidateUserAsync_DuplicateEmailAndPassword_CustomErrors_ErrorsReturned(
            FastUser user,
            MongoFastAuthOptions authOptions)
        {
            user.Email = "test@test.com";
            user.Id = null;
            var password = "test";
            TestUserValidator userValidator = new((_, _) => 
            {
                Dictionary<string, List<string>> errors = new()
                {
                    ["TestField"] = new() { "Some Error" }
                };
                return (false, errors)!;
            });

            await using MongoDBProvider dbProvider = new();
            authOptions.MongoDatabaseGetter = _ => dbProvider.TestDatabase;

            var usersCollections = dbProvider.TestDatabase.GetCollection<FastUser>("FastUsers");
            await usersCollections.InsertOneAsync(user);

            FastUserStore<FastUser, FastRefreshToken> userStore = new(authOptions, null!, userValidator);

            var result = await userStore.ValidateUserAsync(user, password);

            result.Should().NotBeNull();
            result.Should().HaveCount(3);
            result!.ContainsKey(nameof(FastUser.Email)).Should().BeTrue();
            result!.ContainsKey("Password").Should().BeTrue();
            result!.ContainsKey("TestField").Should().BeTrue();
        }

        [Theory, MoreAutoData]
        public async Task ValidateUserAsync_AllOkay_NullReturned(MongoFastAuthOptions authOptions)
        {
            FastUser user = new() { Email = "test@test.com", NormalizedEmail = "TEST@TEST.COM" };
            var password = "test1234";

            await using MongoDBProvider dbProvider = new();

            authOptions.MongoDatabaseGetter = _ => dbProvider.TestDatabase;
            FastUserStore<FastUser, FastRefreshToken> userStore = new(authOptions, null!);

            var result = await userStore.ValidateUserAsync(user, password);

            result.Should().BeNull();
        }
    }
}
