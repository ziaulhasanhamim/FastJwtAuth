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
using NSubstitute.Extensions;

public class FastAuthServiceTests
{
    [Fact]
    public async Task CreateUserAsync_InvalidInput_FailureAuthResult()
    {
        FastUser user = new()
        {
            Email = "Test@test.com"
        };
        var password = "pass";

        var userValidator = Substitute.For<IFastUserValidator<FastUser>>();

        userValidator.ValidateAsync(user, password)
            .Returns((false, new() { "SomeOtherError" }));

        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(userValidator);

        authService.Configure()
            .DoesNormalizedEmailExistAsyncMock(authService.NormalizeText(user.Email), default)
            .Returns(true);

        var result = await authService.CreateUserAsync(user, password);

        result.Success.Should().BeFalse();
        result.ErrorCodes.Should().HaveCount(3);
        result.ErrorCodes.Should()
            .Contain(new[] { "SomeOtherError", FastAuthErrorCodes.PasswordVeryShort, FastAuthErrorCodes.DuplicateEmail });
    }

    [Fact]
    public async Task CreateUserAsync_ValidInput_SuccessAuthResult()
    {
        FastUser user = new()
        {
            Email = "teat@Test.com"
        };
        var password = "testpass";

        FastAuthOptionsTestImpl fastAuthOptions = new()
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

        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions);

        authService.Configure().CreateRefreshTokenAsyncMock(user, default)
            .Returns(refreshToken);

        var result = await authService.CreateUserAsync(user, password);

        result.ErrorCodes.Should().BeNull();
        result.Success.Should().BeTrue();

        user.NormalizedEmail.Should().Be(user.Email.Normalize().ToUpperInvariant());
        user.CreatedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));
        user.LastLogin.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));

        authService.Received(1).HashPassword(password);
        await authService.Received(1).AddUserAsyncMock(user, default);
    }

    [Fact]
    public async Task LoginUserAsync_InvalidEmail_FailureAuthResult()
    {
        var userIdentifier = "test@mail.com";
        var password = "testpass";
        var authService = Substitute.For<FastAuthServiceMock>();

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
            Email = "teSt@test.com"
        };
        var password = "testpass";
        var authService = Substitute.For<FastAuthServiceMock>();
        authService.GetUserByNormalizedEmailAsyncMock(authService.NormalizeText(user.Email)!, default)
            .Returns(user);

        var result = await authService.AuthenticateAsync(user.Email!, password);

        var failureResult = result.Should().BeOfType<AuthResult<FastUser>.Failure>()
            .Which;

        failureResult.ErrorCodes.Should().HaveCount(1);
        failureResult.ErrorCodes.Should().Contain(FastAuthErrorCodes.WrongPassword);

        authService.Received(1).VerifyPassword(password, user.PasswordHash!);
    }

    [Fact]
    public async Task LoginUserAsync_ValidInput_SuccessAuthResult()
    {
        FastUser user = new()
        {
            Email = "Test@test.com"
        };
        var password = "testpass";

        FastAuthOptionsTestImpl fastAuthOptions = new()
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

        var authService = Substitute.For<FastAuthServiceMock>(fastAuthOptions);
        authService.GetUserByNormalizedEmailAsyncMock(authService.NormalizeText(user.Email!), default)
            .Returns(user);

        authService.VerifyPassword(password, user.PasswordHash!)
            .Returns(true);

        authService.CreateRefreshTokenAsyncMock(user, default)
            .Returns(refreshToken);

        List<Claim> claims = new() { new("Id", user.Id.ToString()) };
        authService.GetClaimsForUser(user)
            .Returns(claims);

        var result = await authService.AuthenticateAsync(user.Email!, password);

        commonAssert(user, refreshToken, fastAuthOptions, securityKey, result);

        user.LastLogin.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));

        await authService.Received(1).UpdateUserAsyncMock(user, default);
    }

    [Fact]
    public async Task RefreshAsync_InvalidRefreshToken_FailureAuthResult()
    {
        var refreshToken = "dsajhdjkahsdjkhasdkjasjdasd";

        FastAuthOptionsTestImpl fastAuthOptions = new()
        {
            UseRefreshToken = true,
            AccessTokenLifeSpan = TimeSpan.FromMinutes(15),
            RefreshTokenLifeSpan = TimeSpan.FromDays(15)
        };

        var authService = Substitute.For<FastAuthServiceMock>(fastAuthOptions);

        authService.GetRefreshTokenByIdAsyncMock(refreshToken, default)
            .Returns((null, null));

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

        FastAuthOptionsTestImpl fastAuthOptions = new()
        {
            UseRefreshToken = true,
            AccessTokenLifeSpan = TimeSpan.FromMinutes(15),
            RefreshTokenLifeSpan = TimeSpan.FromDays(15)
        };

        var authService = Substitute.For<FastAuthServiceMock>(fastAuthOptions);
        authService.GetRefreshTokenByIdAsyncMock(refreshToken.Id!, default)
            .Returns((refreshToken, user));

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
        FastAuthOptionsTestImpl fastAuthOptions = new()
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

        var authService = Substitute.For<FastAuthServiceMock>(fastAuthOptions);
        authService.GetRefreshTokenByIdAsyncMock(refreshToken.Id!, default)
            .Returns((refreshToken, user));

        authService.CreateRefreshTokenAsyncMock(user, default)
            .Returns(refreshToken);

        List<Claim> claims = new() { new("Id", user.Id.ToString()) };
        authService.GetClaimsForUser(user)
            .Returns(claims);

        var result = await authService.RefreshAsync(refreshToken.Id!);

        commonAssert(user, refreshToken, fastAuthOptions, securityKey, result);

        await authService.Received(1).RemoveRefreshTokenAsyncMock(refreshToken, default);
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
