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
            [Frozen] IFastUserStore<FastUser, FastRefreshToken> userStore,
            FastAuthService<FastUser, FastRefreshToken> authService)
        {
            Dictionary<string, List<string>> errors = new()
            {
                ["Password"] = new() { "Password is too short" }
            };
            userStore.ValidateUserAsync(user, password)
                .Returns(errors);

            var result = await authService.CreateUserAsync(user, password);

            result.Should().BeOfType<FailureAuthResult<FastUser>>()
                .Which.Errors.Should().HaveCount(1);
        }

        [Theory, MoreAutoData]
        public async Task CreateUserAsync_ValidInput_SuccessAuthResult(
            FastUser user,
            string password,
            FastRefreshToken refreshToken,
            [Frozen] FastAuthOptions fastAuthOptions,
            [Frozen] IFastUserStore<FastUser, FastRefreshToken> userStore,
            FastAuthService<FastUser, FastRefreshToken> authService)
        {
            fastAuthOptions.UseRefreshToken = true;
            fastAuthOptions.AccessTokenLifeSpan = TimeSpan.FromMinutes(15);
            fastAuthOptions.RefreshTokenLifeSpan = TimeSpan.FromDays(15);
            refreshToken.ExpiresAt = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan;
            SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
            SigningCredentials signingCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

            userStore.CreateRefreshTokenAsync(user, default)
                .Returns(refreshToken);

            userStore.GetRefreshTokenIdentifier(refreshToken)
                .Returns(refreshToken.Id);

            userStore.GetRefreshTokenExpireDate(refreshToken)
                .Returns(refreshToken.ExpiresAt);

            Claim[] claims = { new("Id", user.Id.ToString()) };
            userStore.GetClaimsForUser(user)
                .Returns(claims);

            var result = await authService.CreateUserAsync(user, password, true, signingCredentials);

            assertResult(user, refreshToken, fastAuthOptions, securityKey, result);

            userStore.Received(1).SetPassword(user, password);
            userStore.Received(1).SetCreationDateTimes(user);
            userStore.Received(1).SetLoginDateTimes(user);
            await userStore.Received(1).CreateUserAsync(user);
        }

        [Theory, MoreAutoData]
        public async Task LoginUserAsync_InvalidEmail_FailureAuthResult(
            string userIdentifier,
            string password,
            [Frozen] IFastUserStore<FastUser, FastRefreshToken> userStore,
            FastAuthService<FastUser, FastRefreshToken> authService)
        {
            userStore.GetUserByIdentifierAsync(userIdentifier)
                .Returns((FastUser)null!);

            var result = await authService.LoginUserAsync(userIdentifier, password);

            var failureResult = result.Should().BeOfType<FailureAuthResult<FastUser>>()
                .Which;

            failureResult.Errors.Should().HaveCount(1);
            failureResult.Errors!.ContainsKey("UserIdentifier").Should().BeTrue();
        }

        [Theory, MoreAutoData]
        public async Task LoginUserAsync_InvalidPassword_FailureAuthResult(
            FastUser user,
            string password,
            [Frozen] IFastUserStore<FastUser, FastRefreshToken> userStore,
            FastAuthService<FastUser, FastRefreshToken> authService)
        {
            userStore.GetUserByIdentifierAsync(user.Email!)
                .Returns(user);

            userStore.VerifyPassword(user, password)
                .Returns(false);

            var result = await authService.LoginUserAsync(user.Email!, password);

            var failureResult = result.Should().BeOfType<FailureAuthResult<FastUser>>()
                .Which;

            failureResult.Errors.Should().HaveCount(1);
            failureResult.Errors!.ContainsKey("Password").Should().BeTrue();
        }

        [Theory, MoreAutoData]
        public async Task LoginUserAsync_ValidInput_SuccessAuthResult(
            FastUser user,
            string password,
            FastRefreshToken refreshToken,
            [Frozen] FastAuthOptions fastAuthOptions,
            [Frozen] IFastUserStore<FastUser, FastRefreshToken> userStore,
            FastAuthService<FastUser, FastRefreshToken> authService)
        {
            fastAuthOptions.UseRefreshToken = true;
            fastAuthOptions.AccessTokenLifeSpan = TimeSpan.FromMinutes(15);
            fastAuthOptions.RefreshTokenLifeSpan = TimeSpan.FromDays(15);
            refreshToken.ExpiresAt = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan;
            SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
            fastAuthOptions.DefaultSigningCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

            userStore.GetUserByIdentifierAsync(user.Email!)
                .Returns(user);

            userStore.VerifyPassword(user, password)
                .Returns(true);

            userStore.CreateRefreshTokenAsync(user)
                .Returns(refreshToken);

            userStore.GetRefreshTokenIdentifier(refreshToken)
                .Returns(refreshToken.Id);

            userStore.GetRefreshTokenExpireDate(refreshToken)
                .Returns(refreshToken.ExpiresAt);

            Claim[] claims = { new("Id", user.Id.ToString()) };
            userStore.GetClaimsForUser(user)
                .Returns(claims);

            var result = await authService.LoginUserAsync(user.Email!, password);

            assertResult(user, refreshToken, fastAuthOptions, securityKey, result);

            userStore.Received(1).SetLoginDateTimes(user);
            await userStore.Received(1).UpdateUserAsync(user);
        }

        [Theory, MoreAutoData]
        public async Task RefreshAsync_InvalidRefreshToken_FailureAuthResult(
            string refreshToken,
            [Frozen] IFastUserStore<FastUser, FastRefreshToken> userStore,
            FastAuthService<FastUser, FastRefreshToken> authService)
        {
            userStore.GetRefreshTokenByIdentifierAsync(refreshToken)
                .Returns((null, null));

            var result = await authService.RefreshAsync(refreshToken);

            var failureResult = result.Should().BeOfType<FailureAuthResult<FastUser>>()
                .Which;

            failureResult.Title.Should().NotBeNullOrWhiteSpace();
            failureResult.Errors.Should().BeNull();
        }

        [Theory, MoreAutoData]
        public async Task RefreshAsync_ExpiredRefreshToken_FailureAuthResult(
            FastUser user,
            FastRefreshToken refreshToken,
            [Frozen] IFastUserStore<FastUser, FastRefreshToken> userStore,
            FastAuthService<FastUser, FastRefreshToken> authService)
        {
            userStore.GetRefreshTokenByIdentifierAsync(refreshToken.Id!)
                .Returns((refreshToken, user));

            userStore.IsRefreshTokenExpired(refreshToken)
                .Returns(true);

            var result = await authService.RefreshAsync(refreshToken.Id!);

            var failureResult = result.Should().BeOfType<FailureAuthResult<FastUser>>()
                .Which;

            failureResult.Title.Should().NotBeNullOrWhiteSpace();
            failureResult.Errors.Should().BeNull();
        }

        [Theory, MoreAutoData]
        public async Task RefreshAsync_ValidRefreshToken_SuccessAuthResult(
            FastUser user,
            FastRefreshToken refreshToken,
            [Frozen] FastAuthOptions fastAuthOptions,
            [Frozen] IFastUserStore<FastUser, FastRefreshToken> userStore,
            FastAuthService<FastUser, FastRefreshToken> authService)
        {
            fastAuthOptions.UseRefreshToken = true;
            fastAuthOptions.AccessTokenLifeSpan = TimeSpan.FromMinutes(15);
            fastAuthOptions.RefreshTokenLifeSpan = TimeSpan.FromDays(15);
            refreshToken.ExpiresAt = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan;
            SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
            SigningCredentials signingCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

            userStore.GetRefreshTokenByIdentifierAsync(refreshToken.Id!)
                .Returns((refreshToken, user));

            userStore.CreateRefreshTokenAsync(user)
                .Returns(refreshToken);

            userStore.GetRefreshTokenIdentifier(refreshToken)
                .Returns(refreshToken.Id);

            userStore.GetRefreshTokenExpireDate(refreshToken)
                .Returns(refreshToken.ExpiresAt);

            Claim[] claims = { new("Id", user.Id.ToString()) };
            userStore.GetClaimsForUser(user)
                .Returns(claims);

            var result = await authService.RefreshAsync(refreshToken.Id!, signingCredentials);

            assertResult(user, refreshToken, fastAuthOptions, securityKey, result);

            await userStore.Received(1).MakeRefreshTokenUsedAsync(refreshToken);
        }

        private static void assertResult(FastUser user, FastRefreshToken refreshToken, FastAuthOptions fastAuthOptions, SymmetricSecurityKey securityKey, IAuthResult<FastUser> result)
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
