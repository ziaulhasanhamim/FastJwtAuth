using FastJwtAuth.Abstractions.Dtos;
using FastJwtAuth.Abstractions.Services;
using FastJwtAuth.Core.Options;
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
    {
        private readonly IFastUserStore<TUser, TRefreshToken> _userStore;
        private readonly FastAuthOptions _authOptions;

        public FastAuthService(IFastUserStore<TUser, TRefreshToken> userStore, FastAuthOptions authOptions)
        {
            _userStore = userStore;
            _authOptions = authOptions;
        }

        public async Task<IAuthResult<TUser>> CreateUserAsync(TUser user, string password, CancellationToken cancellationToken = default)
        {
            var validation_errors = await _userStore.ValidateUserAsync(user, password, cancellationToken);
            if (validation_errors is not null)
            {
                return new FailureAuthResult<TUser>("Fix The specified errors", validation_errors);
            }

            _userStore.SetPassword(user, password);
            _userStore.SetCreationDateTimes(user);
            _userStore.SetLoginDateTimes(user);
            await _userStore.CreateUserAsync(user, cancellationToken);

            return await generateTokens(user, cancellationToken);
        }

        public Task<IAuthResult<TUser>> LoginUserAsync(string loginIdentifier, string password, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IAuthResult<TUser>> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        private async Task<SuccessAuthResult<TUser>> generateTokens(TUser user, CancellationToken cancellationToken)
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
                signingCredentials: _authOptions.SigningCredentials);
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
