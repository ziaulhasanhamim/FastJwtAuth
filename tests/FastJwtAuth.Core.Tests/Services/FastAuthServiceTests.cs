namespace FastJwtAuth.Core.Tests.Services;

using FastJwtAuth.Core.Services;
using FastJwtAuth;
using FastJwtAuth.Core.Tests.Entities;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Xunit;
using System.Text;

public class FastAuthServiceTests
{
    [Fact]
    public async Task CreateUserAsync_InvalidInput_FailureAuthResult()
    {
        FastUser user = new()
        {
            Email = "test@test.com"
        };
        var password = "testpass";
        List<string> errors = new() { FastAuthErrorCodes.PasswordVeryShort };

        var userStore = Substitute.For<IFastUserStore<FastUser, FastRefreshToken, Guid>>();

        FastAuthService<FastUser, FastRefreshToken, Guid> authService = new(userStore, new());

        userStore.ValidateUserAsync(user, password)
            .Returns(errors);

        var result = await authService.CreateUserAsync(user, password);

        result.Success.Should().BeFalse();
        result.ErrorCodes.Should().HaveCount(1);
    }

    [Fact]
    public async Task CreateUserAsync_ValidInput_SuccessAuthResult()
    {
        FastUser user = new()
        {
            Email = "teat@Test.com"
        };
        var password = "test";

        FastAuthOptions<FastUser, FastRefreshToken, Guid> fastAuthOptions = new()
        {
            UseRefreshToken = true,
            AccessTokenLifeSpan = TimeSpan.FromMinutes(15),
            RefreshTokenLifeSpan = TimeSpan.FromDays(15)
        };
        FastRefreshToken refreshToken = new()
        {
            Id = Guid.NewGuid().ToString(),
            ExpiresAt = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan
        };
        SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
        fastAuthOptions.DefaultSigningCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

        var userStore = Substitute.For<IFastUserStore<FastUser, FastRefreshToken, Guid>>();

        userStore.NormalizeEmail(Arg.Any<string>())
            .Returns(callInfo => callInfo.ArgAt<string>(0).Normalize().ToUpperInvariant());

        userStore.CreateRefreshTokenAsync(user, default)
            .Returns(refreshToken);

        Claim[] claims = { new("Id", user.Id.ToString()) };
        userStore.GetClaimsForUser(user)
            .Returns(claims);

        FastAuthService<FastUser, FastRefreshToken, Guid> authService = new(userStore, fastAuthOptions);

        var result = await authService.CreateUserAsync(user, password);

        result.ErrorCodes.Should().BeNull();
        result.Success.Should().BeTrue();

        user.NormalizedEmail.Should().Be(user.Email.Normalize().ToUpperInvariant());
        user.CreatedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));
        user.LastLogin.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));

        userStore.Received(1).HashPassword(password);
        await userStore.Received(1).CreateUserAsync(user);
    }

    [Fact]
    public async Task LoginUserAsync_InvalidEmail_FailureAuthResult()
    {
        var userIdentifier = "test@mail.com";
        var password = "testpass";
        var userStore = Substitute.For<IFastUserStore<FastUser, FastRefreshToken, Guid>>();
        userStore.GetUserByEmailAsync(userIdentifier)
            .Returns((FastUser)null!);

        FastAuthService<FastUser, FastRefreshToken, Guid> authService = new(userStore, new());
        var result = await authService.AuthenticateAsync(userIdentifier, password);

        var failureResult = result.Should().BeOfType<AuthResult<FastUser>.Failure>()
            .Which;

        failureResult.ErrorCodes.Should().HaveCount(1);
        failureResult.ErrorCodes.Should().Contain(FastAuthErrorCodes.WrongEmail);
    }

    [Fact]
    public async Task LoginUserAsync_InvalidPassword_FailureAuthResult()
    {
        FastUser user = new()
        {
            Email = "test@test.com"
        };
        var password = "testpass";
        var userStore = Substitute.For<IFastUserStore<FastUser, FastRefreshToken, Guid>>();
        userStore.GetUserByEmailAsync(user.Email!)
            .Returns(user);

        FastAuthService<FastUser, FastRefreshToken, Guid> authService = new(userStore, new());

        var result = await authService.AuthenticateAsync(user.Email!, password);

        var failureResult = result.Should().BeOfType<AuthResult<FastUser>.Failure>()
            .Which;

        failureResult.ErrorCodes.Should().HaveCount(1);
        failureResult.ErrorCodes.Should().Contain(FastAuthErrorCodes.WrongPassword);

        userStore.Received(1).VerifyPassword(password, user.PasswordHash!);
    }

    [Fact]
    public async Task LoginUserAsync_ValidInput_SuccessAuthResult()
    {
        FastUser user = new()
        {
            Email = "test@test.com"
        };
        var password = "testpass";

        FastAuthOptions<FastUser, FastRefreshToken, Guid> fastAuthOptions = new()
        {
            UseRefreshToken = true,
            AccessTokenLifeSpan = TimeSpan.FromMinutes(15),
            RefreshTokenLifeSpan = TimeSpan.FromDays(15)
        };

        FastRefreshToken refreshToken = new()
        {
            ExpiresAt = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan
        };

        SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
        fastAuthOptions.DefaultSigningCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

        var userStore = Substitute.For<IFastUserStore<FastUser, FastRefreshToken, Guid>>();
        userStore.GetUserByEmailAsync(user.Email!)
            .Returns(user);

        userStore.VerifyPassword(password, user.PasswordHash!)
            .Returns(true);

        userStore.CreateRefreshTokenAsync(user)
            .Returns(refreshToken);

        Claim[] claims = { new("Id", user.Id.ToString()) };
        userStore.GetClaimsForUser(user)
            .Returns(claims);

        FastAuthService<FastUser, FastRefreshToken, Guid> authService = new(userStore, fastAuthOptions);
        var result = await authService.AuthenticateAsync(user.Email!, password);

        commonAssert(user, refreshToken, fastAuthOptions, securityKey, result);

        user.LastLogin.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));

        await userStore.Received(1).UpdateUserAsync(user);
    }

    [Fact]
    public async Task RefreshAsync_InvalidRefreshToken_FailureAuthResult()
    {
        var refreshToken = "dsajhdjkahsdjkhasdkjasjdasd";

        var userStore = Substitute.For<IFastUserStore<FastUser, FastRefreshToken, Guid>>();
        userStore.GetRefreshTokenByIdAsync(refreshToken)
            .Returns((null, null));

        FastAuthService<FastUser, FastRefreshToken, Guid> authService = new(userStore, new() { UseRefreshToken = true });
        var result = await authService.RefreshAsync(refreshToken);

        result.Should()
            .BeOfType<AuthResult<FastUser>.Failure>()
            .Which
            .ErrorCodes
            .Should()
            .HaveCount(1)
            .And
            .Contain(FastAuthErrorCodes.InvalidRefreshToken);
    }

    [Fact]
    public async Task RefreshAsync_ExpiredRefreshToken_FailureAuthResult()
    {
        FastUser user = new()
        {
            Email = "test@test.com"
        };
        FastRefreshToken refreshToken = new()
        {
            Id = Guid.NewGuid().ToString(),
            ExpiresAt = DateTime.UtcNow - TimeSpan.FromHours(1)
        };

        var userStore = Substitute.For<IFastUserStore<FastUser, FastRefreshToken, Guid>>();
        userStore.GetRefreshTokenByIdAsync(refreshToken.Id!)
            .Returns((refreshToken, user));

        FastAuthService<FastUser, FastRefreshToken, Guid> authService = new(userStore, new() { UseRefreshToken = true });
        var result = await authService.RefreshAsync(refreshToken.Id!);

        result.Should()
            .BeOfType<AuthResult<FastUser>.Failure>()
            .Which
            .ErrorCodes
            .Should()
            .HaveCount(1)
            .And
            .Contain(FastAuthErrorCodes.ExpiredRefreshToken);
    }

    [Fact]
    public async Task RefreshAsync_ValidRefreshToken_SuccessAuthResult()
    {
        FastUser user = new()
        {
            Email = "test@test.com"
        };
        FastAuthOptions<FastUser, FastRefreshToken, Guid> fastAuthOptions = new()
        {
            UseRefreshToken = true,
            AccessTokenLifeSpan = TimeSpan.FromMinutes(15),
            RefreshTokenLifeSpan = TimeSpan.FromDays(15)
        };
        FastRefreshToken refreshToken = new()
        {
            Id = Guid.NewGuid().ToString(),
            ExpiresAt = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan
        };
        SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
        fastAuthOptions.DefaultSigningCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

        var userStore = Substitute.For<IFastUserStore<FastUser, FastRefreshToken, Guid>>();
        userStore.GetRefreshTokenByIdAsync(refreshToken.Id!)
            .Returns((refreshToken, user));

        userStore.CreateRefreshTokenAsync(user)
            .Returns(refreshToken);

        Claim[] claims = { new("Id", user.Id.ToString()) };
        userStore.GetClaimsForUser(user)
            .Returns(claims);

        FastAuthService<FastUser, FastRefreshToken, Guid> authService = new(userStore, fastAuthOptions);
        var result = await authService.RefreshAsync(refreshToken.Id!);

        commonAssert(user, refreshToken, fastAuthOptions, securityKey, result);

        await userStore.Received(1).RemoveRefreshTokenAsync(refreshToken);
    }

    private static void commonAssert(
        FastUser user, 
        FastRefreshToken refreshToken, 
        FastAuthOptions<FastUser, FastRefreshToken, Guid> fastAuthOptions, 
        SymmetricSecurityKey securityKey, 
        AuthResult<FastUser> result)
    {
        var successResult = result.Should().BeOfType<AuthResult<FastUser>.Success>().Which;
        successResult.RefreshToken.Should().Be(refreshToken.Id);
        successResult.RefreshTokenExpiresAt.Should().Be(refreshToken.ExpiresAt);
        successResult.AccessTokenExpiresAt.Should().BeCloseTo(
            DateTimeOffset.UtcNow.Add(fastAuthOptions.AccessTokenLifeSpan),
            TimeSpan.FromMinutes(1));
        TokenValidationParameters validationParams = new()
        {
            IssuerSigningKey = securityKey,
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
            ValidateLifetime = true,
            ValidateIssuer = false,
            ValidateAudience = false
        };
        JwtSecurityTokenHandler tokenHandler = new();
        var claimPrinciple = tokenHandler.ValidateToken(successResult.AccessToken, validationParams, out _);
        claimPrinciple.Claims.First(c => c.Type == "Id").Value.Should().Be(user.Id.ToString());
    }
}
