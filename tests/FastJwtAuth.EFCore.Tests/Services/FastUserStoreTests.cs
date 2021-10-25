using AutoFixture.Xunit2;
using FastJwtAuth.EFCore.Services;
using FastJwtAuth.EFCore.Tests.AutofixtureUtils;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using NSubstitute;
using NSubstitute.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace FastJwtAuth.EFCore.Tests.Services
{
    public class FastUserStoreTests
    {
        [Theory, MoreAutoData]
        public async Task ValidateUserAsync_InvalidEmailAndPassword_CustomErrors_ErrorsReturned(
            FastUser user,
            FastAuthOptions authOptions)
        {
            user.Email = "test";
            var password = "test";
            TestUserValidator userValidator = new(user => 
            {
                Dictionary<string, List<string>> errors = new()
                {
                    ["TestField"] = new() { "Some Error" }
                };
                return (false, errors)!;
            });

            FastUserStore<FastUser, Guid, FastRefreshToken, DbContext> userStore = new(null!, authOptions, userValidator);

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
            FastAuthOptions authOptions)
        {
            user.Email = "test@test.com";
            var password = "test";
            TestUserValidator userValidator = new(user => 
            {
                Dictionary<string, List<string>> errors = new()
                {
                    ["TestField"] = new() { "Some Error" }
                };
                return (false, errors)!;
            });

            await using var dbContext = await TestDbContext.InitAsync();

            dbContext.Add(user);
            await dbContext.SaveChangesAsync();

            FastUserStore<FastUser, Guid, FastRefreshToken, DbContext> userStore = new(dbContext, authOptions, userValidator);

            var result = await userStore.ValidateUserAsync(user, password);

            result.Should().NotBeNull();
            result.Should().HaveCount(3);
            result!.ContainsKey(nameof(FastUser.Email)).Should().BeTrue();
            result!.ContainsKey("Password").Should().BeTrue();
            result!.ContainsKey("TestField").Should().BeTrue();
        }

        [Fact]
        public async Task ValidateUserAsync_AllOkay_NullReturned()
        {
            FastUser user = new() { Email = "test@test.com" };
            var password = "test1234";

            await using var dbContext = await TestDbContext.InitAsync();

            FastUserStore<FastUser, Guid, FastRefreshToken, DbContext> userStore = new(dbContext, new());

            var result = await userStore.ValidateUserAsync(user, password);

            result.Should().BeNull();
        }
    }
}
