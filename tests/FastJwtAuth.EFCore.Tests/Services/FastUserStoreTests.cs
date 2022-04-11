namespace FastJwtAuth.EFCore.Tests.Services;

using FastJwtAuth.EFCore.Services;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
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

        FastUserStore<FastUser, FastRefreshToken, DbContext> userStore = new(null!, new(), userValidator);

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
        var password = "test";
        FastUser user = new()
        {
            Email = "test@test.com",
            NormalizedEmail = "test@test.com".Normalize().ToUpperInvariant(),
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password)
        };
        
        TestUserValidator userValidator = new((_, _) =>
        {
            return (false, new() { "OtherErrorCode" });
        });

        await using var dbContext = await TestDbContext.InitAsync();

        dbContext.Add(user);
        await dbContext.SaveChangesAsync();

        FastUserStore<FastUser, FastRefreshToken, DbContext> userStore = new(dbContext, new(), userValidator);

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
