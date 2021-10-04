using AutoFixture.Xunit2;
using FastJwtAuth.EFCore.Entities;
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
            authOptions.OnUserValidate = (_, _) =>
            {
                return Task.FromResult(new Dictionary<string, List<string>>()
                {
                    ["TestField"] = new() { "Some Error" }
                });
            };

            FastUserStore<FastUser, FastRefreshToken, DbContext> userStore = new(null!, authOptions);

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
            authOptions.OnUserValidate = (_, _) =>
            {
                return Task.FromResult(new Dictionary<string, List<string>>()
                {
                    ["TestField"] = new() { "Some Error" }
                });
            };

            using var dbContext = new TestDbContext();

            dbContext.Add(user);

            FastUserStore<FastUser, FastRefreshToken, DbContext> userStore = new(dbContext, authOptions);

            var result = await userStore.ValidateUserAsync(user, password);

            result.Should().NotBeNull();
            result.Should().HaveCount(3);
            result!.ContainsKey(nameof(FastUser.Email)).Should().BeTrue();
            result!.ContainsKey("Password").Should().BeTrue();
            result!.ContainsKey("TestField").Should().BeTrue();
        }
    }
}
