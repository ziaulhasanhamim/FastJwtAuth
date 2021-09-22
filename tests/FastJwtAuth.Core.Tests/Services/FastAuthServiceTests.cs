using AutoFixture.Xunit2;
using FastJwtAuth.Abstractions.Dtos;
using FastJwtAuth.Abstractions.Services;
using FastJwtAuth.Core.Options;
using FastJwtAuth.Core.Services;
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
            [Frozen] IFastUserStore<FastUser, RefreshToken> userStore,
            FastAuthService<FastUser, RefreshToken> authService)
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
            RefreshToken refreshToken,
            [Frozen] FastAuthOptions fastAuthOptions,
            [Frozen] IFastUserStore<FastUser, RefreshToken> userStore,
            FastAuthService<FastUser, RefreshToken> authService)
        {
            fastAuthOptions.UseRefreshToken = true;
            fastAuthOptions.AccessTokenLifeSpan = TimeSpan.FromMinutes(15);
            fastAuthOptions.RefreshTokenLifeSpan = TimeSpan.FromDays(15);
            refreshToken.ExpireDate = DateTime.UtcNow + fastAuthOptions.RefreshTokenLifeSpan;
            SymmetricSecurityKey securityKey = new(Encoding.Unicode.GetBytes("dasdbasdhgaysgduyasd7623t3t276t326t362t3dsgagdgad"));
            fastAuthOptions.SigningCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

            userStore.CreateRefreshTokenAsync(user, default)
                .Returns(refreshToken);

            userStore.GetRefreshTokenIdentifier(refreshToken)
                .Returns(refreshToken.Id);

            userStore.GetRefreshTokenExpireDate(refreshToken)
                .Returns(refreshToken.ExpireDate);

            Claim[] claims = { new("Id", user.Id.ToString()) };
            userStore.GetClaimsForUser(user)
                .Returns(claims);

            var result = await authService.CreateUserAsync(user, password);

            assertResult(user, refreshToken, fastAuthOptions, securityKey, result);

            userStore.Received(1).SetPassword(user, password);
            userStore.Received(1).SetCreationDateTimes(user);
            await userStore.Received(1).CreateUserAsync(user);
        }

        private static void assertResult(FastUser user, RefreshToken refreshToken, FastAuthOptions fastAuthOptions, SymmetricSecurityKey securityKey, IAuthResult<FastUser> result)
        {
            var successResult = result.Should().BeOfType<SuccessAuthResult<FastUser>>().Which;
            successResult.RefreshToken.Should().Be(refreshToken.Id);
            successResult.RefreshTokenExpiresAt.Should().Be(refreshToken.ExpireDate);
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
