namespace FastJwtAuth.Core.Tests.Services;

using AutoFixture.Xunit2;
using FastJwtAuth.Core.Services;
using FastJwtAuth;
using FastJwtAuth.Core.Tests.AutofixtureUtils;
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
    [Theory, MoreAutoData]
    public async Task CreateUserAsync_InvalidInput_FailureAuthResult(
        FastUser user,
        string password,
        [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
        [Frozen] FastAuthService<FastUser, FastRefreshToken, Guid> authService)
    {
        List<string> errors = new() { FastAuthErrorCodes.PasswordVeryShort };
        userStore.ValidateUserAsync(user, password)
            .Returns(errors);

        var result = await authService.CreateUserAsync(user, password);

        result.Success.Should().BeFalse();
        result.ErrorCodes.Should().HaveCount(1);
    }

    [Theory, MoreAutoData]
    public async Task CreateUserAsync_ValidInput_SuccessAuthResult(
        string password,
        FastRefreshToken refreshToken,
        [Frozen] FastAuthOptions fastAuthOptions,
        [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
        FastAuthService<FastUser, FastRefreshToken, Guid> authService)
    {
        FastUser user = new()
        {
            Email = "teat@Test.com"
        };

        fastAuthOptions.UseRefreshToken = true;
        fastAuthOptions.AccessTokenLifeSpan = TimeSpan.FromMinutes(15);
        fastAuthOptions.RefreshTokenLifeSpan = TimeSpan.FromDays(15);
        refreshToken.ExpiresAt = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan;
        SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
        SigningCredentials signingCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

        userStore.NormalizeEmail(Arg.Any<string>())
            .Returns(callInfo => callInfo.ArgAt<string>(0).Normalize().ToUpperInvariant());

        userStore.CreateRefreshTokenAsync(user, default)
            .Returns(refreshToken);

        Claim[] claims = { new("Id", user.Id.ToString()) };
        userStore.GetClaimsForUser(user)
            .Returns(claims);

        var result = await authService.CreateUserAsync(user, password);

        result.ErrorCodes.Should().BeNull();
        result.Success.Should().BeTrue();

        user.NormalizedEmail.Should().Be(user.Email.Normalize().ToUpperInvariant());
        user.CreatedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));
        user.LastLogin.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));

        userStore.Received(1).HashPassword(password);
        await userStore.Received(1).CreateUserAsync(user);
    }

    [Theory, MoreAutoData]
    public async Task LoginUserAsync_InvalidEmail_FailureAuthResult(
        string userIdentifier,
        string password,
        [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
        FastAuthService<FastUser, FastRefreshToken, Guid> authService)
    {
        userStore.GetUserByEmailAsync(userIdentifier)
            .Returns((FastUser)null!);

        var result = await authService.AuthenticateAsync(userIdentifier, password);

        var failureResult = result.Should().BeOfType<AuthResult<FastUser>.Failure>()
            .Which;

        failureResult.ErrorCodes.Should().HaveCount(1);
        failureResult.ErrorCodes.Should().Contain(FastAuthErrorCodes.WrongEmail);
    }

    [Theory, MoreAutoData]
    public async Task LoginUserAsync_InvalidPassword_FailureAuthResult(
        FastUser user,
        string password,
        [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
        FastAuthService<FastUser, FastRefreshToken, Guid> authService)
    {
        userStore.GetUserByEmailAsync(user.Email!)
            .Returns(user);

        userStore.VerifyPassword(password, user.PasswordHash!)
            .Returns(false);

        var result = await authService.AuthenticateAsync(user.Email!, password);

        var failureResult = result.Should().BeOfType<AuthResult<FastUser>.Failure>()
            .Which;

        failureResult.ErrorCodes.Should().HaveCount(1);
        failureResult.ErrorCodes.Should().Contain(FastAuthErrorCodes.WrongPassword);
    }

    [Theory, MoreAutoData]
    public async Task LoginUserAsync_ValidInput_SuccessAuthResult(
        FastUser user,
        string password,
        FastRefreshToken refreshToken,
        [Frozen] FastAuthOptions fastAuthOptions,
        [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
        FastAuthService<FastUser, FastRefreshToken, Guid> authService)
    {
        user.LastLogin = null;
        fastAuthOptions.UseRefreshToken = true;
        fastAuthOptions.AccessTokenLifeSpan = TimeSpan.FromMinutes(15);
        fastAuthOptions.RefreshTokenLifeSpan = TimeSpan.FromDays(15);
        refreshToken.ExpiresAt = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan;
        SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
        fastAuthOptions.DefaultSigningCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

        userStore.GetUserByEmailAsync(user.Email!)
            .Returns(user);

        userStore.VerifyPassword(password, user.PasswordHash!)
            .Returns(true);

        userStore.CreateRefreshTokenAsync(user)
            .Returns(refreshToken);

        Claim[] claims = { new("Id", user.Id.ToString()) };
        userStore.GetClaimsForUser(user)
            .Returns(claims);

        var result = await authService.AuthenticateAsync(user.Email!, password);

        commonAssert(user, refreshToken, fastAuthOptions, securityKey, result);

        user.LastLogin.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));

        await userStore.Received(1).UpdateUserAsync(user);
    }

    [Theory, MoreAutoData]
    public async Task RefreshAsync_InvalidRefreshToken_FailureAuthResult(
        string refreshToken,
        [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
        FastAuthService<FastUser, FastRefreshToken, Guid> authService)
    {
        userStore.GetRefreshTokenByIdAsync(refreshToken)
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

    [Theory, MoreAutoData]
    public async Task RefreshAsync_ExpiredRefreshToken_FailureAuthResult(
        FastUser user,
        FastRefreshToken refreshToken,
        [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
        FastAuthService<FastUser, FastRefreshToken, Guid> authService)
    {
        refreshToken.ExpiresAt = DateTime.UtcNow - TimeSpan.FromHours(1);
        userStore.GetRefreshTokenByIdAsync(refreshToken.Id!)
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

    [Theory, MoreAutoData]
    public async Task RefreshAsync_ValidRefreshToken_SuccessAuthResult(
        FastUser user,
        FastRefreshToken refreshToken,
        [Frozen] FastAuthOptions fastAuthOptions,
        [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
        FastAuthService<FastUser, FastRefreshToken, Guid> authService)
    {
        fastAuthOptions.UseRefreshToken = true;
        fastAuthOptions.AccessTokenLifeSpan = TimeSpan.FromMinutes(15);
        fastAuthOptions.RefreshTokenLifeSpan = TimeSpan.FromDays(15);
        refreshToken.ExpiresAt = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan;
        SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
        SigningCredentials signingCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

        userStore.GetRefreshTokenByIdAsync(refreshToken.Id!)
            .Returns((refreshToken, user));

        userStore.CreateRefreshTokenAsync(user)
            .Returns(refreshToken);

        Claim[] claims = { new("Id", user.Id.ToString()) };
        userStore.GetClaimsForUser(user)
            .Returns(claims);

        var result = await authService.RefreshAsync(refreshToken.Id!, signingCredentials);

        commonAssert(user, refreshToken, fastAuthOptions, securityKey, result);

        await userStore.Received(1).RemoveRefreshTokenAsync(refreshToken);
    }

    private static void commonAssert(FastUser user, FastRefreshToken refreshToken, FastAuthOptions fastAuthOptions, SymmetricSecurityKey securityKey, AuthResult<FastUser> result)
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
