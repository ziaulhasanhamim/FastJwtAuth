namespace FastJwtAuth.EFCore.Tests.Services;

using FastJwtAuth.EFCore.Services;
using FastJwtAuth.EFCore.Tests.AutofixtureUtils;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using Xunit;


public class FastUserStoreTests
{
    [Theory, MoreAutoData]
    public async Task ValidateUserAsync_InvalidEmailAndPassword_CustomErrors_ErrorsReturned(
        FastUser user,
        FastAuthOptions authOptions)
    {
        user.Email = "test";
        var password = "test";
        TestUserValidator userValidator = new((_, _) =>
        {
            return (false, new() { "OtherErrorCode" });
        });

        FastUserStore<FastUser, FastRefreshToken, DbContext> userStore = new(null!, authOptions, userValidator);

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
        FastAuthOptions authOptions)
    {
        user.Email = "test@test.com";
        var password = "test";
        TestUserValidator userValidator = new((_, _) =>
        {
            return (false, new() { "OtherErrorCode" });
        });

        await using var dbContext = await TestDbContext.InitAsync();

        dbContext.Add(user);
        await dbContext.SaveChangesAsync();

        FastUserStore<FastUser, FastRefreshToken, DbContext> userStore = new(dbContext, authOptions, userValidator);

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
        FastUser user = new() { Email = "test@test.com", NormalizedEmail = "TEST@TEST.COM" };
        var password = "test1234";

        await using var dbContext = await TestDbContext.InitAsync();

        FastUserStore<FastUser, FastRefreshToken, DbContext> userStore = new(dbContext, new());

        var result = await userStore.ValidateUserAsync(user, password);

        result.Should().BeNull();
    }
}
