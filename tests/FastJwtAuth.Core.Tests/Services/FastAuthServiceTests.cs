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
            Email = "Testest.com",
            Username = "userNAME  dasd"
        };
        var password = "pass";

        var userValidator = Substitute.For<IFastUserValidator<FastUser>>();

        userValidator.Validate(user, password)
            .Returns((false, new() { "SomeOtherError" }));

        FastAuthOptionsTestImpl fastAuthOptions = new()
        {
            UseRefreshToken = true,
            DefaultTokenCreationOptions = new TokenCreationOptions()
                .UseDefaultCredentials("very-very-very secret key"),
            HasUsername = true,
            IsUsernameCompulsory = true
        };

        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions, userValidator);

        authService.Configure()
            .DoesNormalizedEmailExistMock(authService.NormalizeText(user.Email), default)
            .Returns(true);

        authService.Configure()
            .DoesNormalizedUsernameExistMock(authService.NormalizeText(user.Username), default)
            .Returns(true);

        var result = await authService.CreateUser(user, password);

        result.Success.Should().BeFalse();
        result.ErrorCodes.Should().HaveCount(4);
        result.ErrorCodes.Should()
            .Contain(new[]
            {
                "SomeOtherError",
                FastAuthErrorCodes.PasswordVeryShort, 
                FastAuthErrorCodes.InvalidEmailFormat,
                FastAuthErrorCodes.InvalidUsernameFormat
            });
    }

    [Fact]
    public async Task CreateUserAsync_DuplicateInput_FailureAuthResult()
    {
        FastUser user = new()
        {
            Email = "Test@test.com",
            Username = "userNAME"
        };
        var password = "pass";

        var userValidator = Substitute.For<IFastUserValidator<FastUser>>();

        userValidator.Validate(user, password)
            .Returns((false, new() { "SomeOtherError" }));

        FastAuthOptionsTestImpl fastAuthOptions = new()
        {
            UseRefreshToken = true,
            DefaultTokenCreationOptions = new TokenCreationOptions()
                .UseDefaultCredentials("very-very-very secret key"),
            HasUsername = true,
            IsUsernameCompulsory = true
        };

        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions, userValidator);

        authService.Configure()
            .DoesNormalizedEmailExistMock(authService.NormalizeText(user.Email), default)
            .Returns(true);

        authService.Configure()
            .DoesNormalizedUsernameExistMock(authService.NormalizeText(user.Username), default)
            .Returns(true);

        var result = await authService.CreateUser(user, password);

        result.Success.Should().BeFalse();
        result.ErrorCodes.Should().HaveCount(4);
        result.ErrorCodes.Should()
            .Contain(new[]
            {
                "SomeOtherError",
                FastAuthErrorCodes.PasswordVeryShort, 
                FastAuthErrorCodes.DuplicateEmail,
                FastAuthErrorCodes.DuplicateUsername
            });
    }

    [Fact]
    public async Task CreateUserAsync_ValidInput_SuccessAuthResult()
    {
        FastUser user = new()
        {
            Email = "teat@Test.com",
            Username = "userName"
        };
        var password = "testpass";

        FastAuthOptionsTestImpl fastAuthOptions = new()
        {
            UseRefreshToken = true,
            DefaultTokenCreationOptions = new TokenCreationOptions()
                .UseDefaultCredentials("very-very-very secret key"),
            HasUsername = true,
            IsUsernameCompulsory = true
        };
        FastRefreshToken refreshToken = new()
        {
            Id = Guid.NewGuid().ToString(),
            ExpiresAt = DateTime.UtcNow + fastAuthOptions.DefaultTokenCreationOptions.RefreshTokenLifeSpan
        };

        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions);

        authService.Configure().CreateRefreshTokenMock(user, default)
            .Returns(refreshToken);

        var result = await authService.CreateUser(user, password);

        result.ErrorCodes.Should().BeNull();
        result.Success.Should().BeTrue();

        user.NormalizedEmail.Should().Be(user.Email.Normalize().ToUpperInvariant());
        user.NormalizedUsername.Should().Be(user.Username.Normalize().ToUpperInvariant());
        user.CreatedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));
        user.LastLogin.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));

        authService.Received(1).HashPassword(password);
        await authService.Received(1).AddUserMock(user, default);
        await authService.Received(1).CommitDbChangesMock(default);
    }

    [Fact]
    public async Task LoginUserAsync_InvalidEmail_FailureAuthResult()
    {
        var userIdentifier = "test@mail.com";
        var password = "testpass";

        FastAuthOptionsTestImpl fastAuthOptions = new()
        {
            UseRefreshToken = true,
            DefaultTokenCreationOptions = new TokenCreationOptions()
                .UseDefaultCredentials("very-very-very secret key")
        };
        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions);

        var result = await authService.Authenticate(userIdentifier, password);

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
            Email = "teSt@test.com",
            PasswordHash = "hashedpass"
        };
        var password = "testpass";

        FastAuthOptionsTestImpl fastAuthOptions = new()
        {
            UseRefreshToken = true,
            DefaultTokenCreationOptions = new TokenCreationOptions()
                .UseDefaultCredentials("very-very-very secret key")
        };

        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions);

        var normalizedEmail = authService.NormalizeText(user.Email);

        authService.Configure()
            .VerifyPassword(password, user.PasswordHash!)
            .Returns(false);

        authService.Configure()
            .GetUserByNormalizedEmailMock(normalizedEmail, default)
            .Returns(user);

        var result = await authService.Authenticate(user.Email!, password);

        var failureResult = result.Should().BeOfType<AuthResult<FastUser>.Failure>()
            .Which;

        failureResult.ErrorCodes.Should().HaveCount(1);
        failureResult.ErrorCodes.Should().Contain(FastAuthErrorCodes.WrongPassword);
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
            DefaultTokenCreationOptions = new TokenCreationOptions()
                .UseDefaultCredentials("very-very-very secret key")
        };

        FastRefreshToken refreshToken = new()
        {
            Id = "refreshtokenId",
            ExpiresAt = DateTime.UtcNow + fastAuthOptions.DefaultTokenCreationOptions.RefreshTokenLifeSpan
        };

        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions);
        authService.Configure()
            .GetUserByNormalizedEmailMock(authService.NormalizeText(user.Email!), default)
            .Returns(user);

        authService.Configure()
            .VerifyPassword(password, user.PasswordHash!)
            .Returns(true);

        authService.CreateRefreshTokenMock(user, default)
            .Returns(refreshToken);

        var result = await authService.Authenticate(user.Email!, password);

        commonAssert(user, refreshToken, fastAuthOptions, result);

        user.LastLogin.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromHours(1));

        await authService.Received(1).UpdateUserLastLoginMock(user, default);
        await authService.Received(1).CommitDbChangesMock(default);
    }

    [Fact]
    public async Task RefreshAsync_InvalidRefreshToken_FailureAuthResult()
    {
        var refreshToken = "refreshtoken-string";

        FastAuthOptionsTestImpl fastAuthOptions = new()
        {
            UseRefreshToken = true,
            DefaultTokenCreationOptions = new TokenCreationOptions()
                .UseDefaultCredentials("very-very-very secret key")
        };

        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions);

        authService.Configure()
            .GetRefreshTokenByIdMock(refreshToken, default)
            .Returns((null, null));

        var result = await authService.Refresh(refreshToken);

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
            DefaultTokenCreationOptions = new TokenCreationOptions()
                .UseDefaultCredentials("very-very-very secret key")
        };

        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions);
        authService.Configure()
            .GetRefreshTokenByIdMock(refreshToken.Id!, default)
            .Returns((refreshToken, user));

        var result = await authService.Refresh(refreshToken.Id!);

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
            DefaultTokenCreationOptions = new TokenCreationOptions()
                .UseDefaultCredentials("very-very-very secret key")
        };
        FastRefreshToken refreshToken = new()
        {
            Id = Guid.NewGuid().ToString(),
            ExpiresAt = DateTime.UtcNow + fastAuthOptions.DefaultTokenCreationOptions.RefreshTokenLifeSpan
        };
        var authService = Substitute.ForPartsOf<FastAuthServiceMock>(fastAuthOptions);
        authService.Configure()
            .GetRefreshTokenByIdMock(refreshToken.Id!, default)
            .Returns((refreshToken, user));

        authService.CreateRefreshTokenMock(user, default)
            .Returns(refreshToken);

        var result = await authService.Refresh(refreshToken.Id!);

        commonAssert(user, refreshToken, fastAuthOptions, result);

        await authService.Received(1).RemoveRefreshTokenMock(refreshToken, default);
        await authService.Received(1).CommitDbChangesMock(default);
    }

    private static void commonAssert(
        FastUser user,
        FastRefreshToken refreshToken,
        FastAuthOptions<FastUser, FastRefreshToken, Guid> fastAuthOptions,
        AuthResult<FastUser> result)
    {
        var successResult = result.Should().BeOfType<AuthResult<FastUser>.Success>().Which;
        successResult.RefreshToken.Should().Be(refreshToken.Id);
        successResult.RefreshTokenExpiresAt.Should().Be(refreshToken.ExpiresAt);
        successResult.AccessTokenExpiresAt.Should().BeCloseTo(
            DateTimeOffset.UtcNow.Add(fastAuthOptions.DefaultTokenCreationOptions!.AccessTokenLifeSpan),
            TimeSpan.FromMinutes(1));
        TokenValidationParameters validationParams = new()
        {
            IssuerSigningKey = fastAuthOptions.DefaultTokenCreationOptions!.SigningCredentials!.Key,
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
            ValidateLifetime = true,
            ValidateIssuer = false,
            ValidateAudience = false,
        };
        JwtSecurityTokenHandler tokenHandler = new()
        {
            MapInboundClaims = false
        };
        var claimPrinciple = tokenHandler.ValidateToken(successResult.AccessToken, validationParams, out _);
        claimPrinciple.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value.Should().Be(user.Id.ToString());
        claimPrinciple.Claims.First(c => c.Type == JwtRegisteredClaimNames.Email).Value.Should().Be(user.Email);
    }
}
