using AutoFixture.Xunit2;
using FastJwtAuth.Core.Services;
using FastJwtAuth;
using FastJwtAuth.Core.Tests.AutofixtureUtils;
using FastJwtAuth.Core.Tests.Entities;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace FastJwtAuth.Core.Tests.Services
{
    public class FastAuthServiceTests
    {
        [Theory, MoreAutoData]
        public async Task CreateUserAsync_InvalidInput_FailureAuthResult(
            FastUser user,
            string password,
            [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
            [Frozen] FastAuthService<FastUser, FastRefreshToken, Guid> authService)
        {
            List<AuthErrorType> errors = new() { AuthErrorType.PasswordVeryShort };
            userStore.ValidateUserAsync(user, password)
                .Returns(errors);

            var result = await authService.CreateUserAsync(user, password);

            result.Should().BeOfType<FailureAuthResult<FastUser>>()
                .Which.Errors.Should().HaveCount(1);
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

            var result = await authService.CreateUserAsync(user, password, true, signingCredentials);

            commonAssert(user, refreshToken, fastAuthOptions, securityKey, result);

            user.NormalizedEmail.Should().Be(user.Email.Normalize().ToUpperInvariant());

            user.CreatedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));
            user.LastLogin.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));

            userStore.Received(1).SetPassword(user, password);

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

            var result = await authService.LoginUserAsync(userIdentifier, password);

            var failureResult = result.Should().BeOfType<FailureAuthResult<FastUser>>()
                .Which;

            failureResult.Errors.Should().HaveCount(1);
            failureResult.Errors.Should().Contain(AuthErrorType.WrongEmail);
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

            userStore.VerifyPassword(user, password)
                .Returns(false);

            var result = await authService.LoginUserAsync(user.Email!, password);

            var failureResult = result.Should().BeOfType<FailureAuthResult<FastUser>>()
                .Which;

            failureResult.Errors.Should().HaveCount(1);
            failureResult.Errors.Should().Contain(AuthErrorType.WrongPassword);
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

            userStore.VerifyPassword(user, password)
                .Returns(true);

            userStore.CreateRefreshTokenAsync(user)
                .Returns(refreshToken);

            Claim[] claims = { new("Id", user.Id.ToString()) };
            userStore.GetClaimsForUser(user)
                .Returns(claims);

            var result = await authService.LoginUserAsync(user.Email!, password);

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
                .BeOfType<FailureAuthResult<FastUser>>()
                .Which
                .Errors
                .Should()
                .HaveCount(1)
                .And
                .Contain(AuthErrorType.InvalidRefreshToken);
        }

        [Theory, MoreAutoData]
        public async Task RefreshAsync_ExpiredRefreshToken_FailureAuthResult(
            FastUser user,
            FastRefreshToken refreshToken,
            [Frozen] IFastUserStore<FastUser, FastRefreshToken, Guid> userStore,
            FastAuthService<FastUser, FastRefreshToken, Guid> authService)
        {
            userStore.GetRefreshTokenByIdAsync(refreshToken.Id!)
                .Returns((refreshToken, user));

            var result = await authService.RefreshAsync(refreshToken.Id!);

            result.Should()
                .BeOfType<FailureAuthResult<FastUser>>()
                .Which
                .Errors
                .Should()
                .HaveCount(1)
                .And
                .Contain(AuthErrorType.ExpiredRefreshToken);
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

        private static void commonAssert(FastUser user, FastRefreshToken refreshToken, FastAuthOptions fastAuthOptions, SymmetricSecurityKey securityKey, IAuthResult<FastUser> result)
        {
            var successResult = result.Should().BeOfType<SuccessAuthResult<FastUser>>().Which;
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
}
