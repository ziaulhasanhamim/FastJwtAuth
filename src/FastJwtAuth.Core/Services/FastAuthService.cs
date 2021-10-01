using FastJwtAuth;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FastJwtAuth.Core.Services
{
    public class FastAuthService<TUser, TRefreshToken> : IFastAuthService<TUser, TRefreshToken>
        where TUser : class
        where TRefreshToken : class
    {
        private readonly IFastUserStore<TUser, TRefreshToken> _userStore;
        private readonly FastAuthOptions _authOptions;

        public FastAuthService(IFastUserStore<TUser, TRefreshToken> userStore, FastAuthOptions authOptions)
        {
            _userStore = userStore;
            _authOptions = authOptions;
        }

        public async Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, SigningCredentials? signingCredentials, Action<TUser>? beforeCreate, CancellationToken cancellationToken = default)
        {
            var validation_errors = await _userStore.ValidateUserAsync(user, password, cancellationToken);
            if (validation_errors is not null)
            {
                return new FailureAuthResult<TUser>("Fix The specified errors", validation_errors);
            }

            _userStore.SetPassword(user, password);
            _userStore.SetCreationDateTimes(user);
            _userStore.SetLoginDateTimes(user);
            beforeCreate?.Invoke(user);
            await _userStore.CreateUserAsync(user, cancellationToken);

            return await generateTokens(user, signingCredentials, cancellationToken);
        }

        public Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
        {
            return CreateUserAsync(user, password, null, null);
        }
        
        public Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
        {
            return CreateUserAsync(user, password, signingCredentials, null);
        }

        public async Task<IAuthResult<TUser>> LoginUserAsync(string userIdentifier, string password, SigningCredentials? signingCredentials, Action<TUser>? beforeLogin, CancellationToken cancellationToken = default)
        {
            var user = await _userStore.GetUserByIdentifierAsync(userIdentifier, cancellationToken);
            if (user is null)
            {
                Dictionary<string, List<string>> validationErrors = new()
                {
                    ["UserIdentifier"] = new() { "User with that identifier was not found" }
                };
                return new FailureAuthResult<TUser>(
                    "Provided credentials were wrong",
                    validationErrors);
            }

            var passwordMatched = _userStore.VerifyPassword(user, password);
            if (!passwordMatched)
            {
                Dictionary<string, List<string>> validationErrors = new()
                {
                    ["Password"] = new() { "Password given for the user was not correct" }
                };
                return new FailureAuthResult<TUser>(
                    "Provided credentials were wrong",
                    validationErrors);
            }

            _userStore.SetLoginDateTimes(user);
            beforeLogin?.Invoke(user);
            await _userStore.UpdateUserAsync(user, cancellationToken);

            return await generateTokens(user, signingCredentials, cancellationToken);
        }

        public Task<IAuthResult<TUser>> LoginUserAsync(string userIdentifier, string password, CancellationToken cancellationToken = default)
        {
            return LoginUserAsync(userIdentifier, password, null, null, cancellationToken);
        }
        
        public Task<IAuthResult<TUser>> LoginUserAsync(string userIdentifier, string password, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
        {
            return LoginUserAsync(userIdentifier, password, signingCredentials, null, cancellationToken);
        }

        public async Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, SigningCredentials? signingCredentials, Action<TUser>? beforeRefresh, CancellationToken cancellationToken = default)
        {
            if (!_authOptions.UseRefreshToken)
            {
                throw new NotImplementedException("FastJwtAuth.Core.Options.FastAuthOptions.UseRefreshToken is false. make it true for refresh");
            }
            var (refreshTokenEntity, user) =  await _userStore.GetRefreshTokenByIdentifierAsync(refreshToken, cancellationToken);
            if (refreshTokenEntity is null)
            {
                return new FailureAuthResult<TUser>("Refresh token is not valid", null);
            }
            if (_userStore.IsRefreshTokenExpired(refreshTokenEntity))
            {
                return new FailureAuthResult<TUser>("Refresh token is expired", null);
            }
            if (_userStore.IsRefreshTokenUsed(refreshTokenEntity))
            {
                return new FailureAuthResult<TUser>("Refresh token is expired", null);
            }
            if (beforeRefresh is not null)
            {
                beforeRefresh(user!);
                await _userStore.UpdateUserAsync(user!, cancellationToken);
            }
            await _userStore.MakeRefreshTokenUsedAsync(refreshTokenEntity, cancellationToken);
            return await generateTokens(user!, signingCredentials, cancellationToken);
        }

        public Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            return RefreshAsync(refreshToken, null, null, cancellationToken);
        }
        
        public Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, SigningCredentials? signingCredentials, CancellationToken cancellationToken = default)
        {
            return RefreshAsync(refreshToken, signingCredentials, null, cancellationToken);
        }

        private async Task<SuccessAuthResult<TUser>> generateTokens(TUser user, SigningCredentials? signingCredentials, CancellationToken cancellationToken)
        {
            string? refreshToken = null;
            DateTime? refreshTokenExpireDate = null;
            if (_authOptions.UseRefreshToken)
            {
                TRefreshToken refreshTokenEntity = await _userStore.CreateRefreshTokenAsync(user, cancellationToken);
                refreshToken = _userStore.GetRefreshTokenIdentifier(refreshTokenEntity);
                refreshTokenExpireDate = _userStore.GetRefreshTokenExpireDate(refreshTokenEntity);
            }
            var claims = _userStore.GetClaimsForUser(user);
            JwtSecurityToken securityToken = new(
                claims: claims,
                expires: DateTime.UtcNow.Add(_authOptions.AccessTokenLifeSpan),
                signingCredentials: signingCredentials ?? _authOptions.DefaultSigningCredentials);
            var accessToken = new JwtSecurityTokenHandler().WriteToken(securityToken);

            return new(
                accessToken,
                securityToken.ValidTo,
                refreshToken,
                refreshTokenExpireDate,
                user);
        }
    }
}
