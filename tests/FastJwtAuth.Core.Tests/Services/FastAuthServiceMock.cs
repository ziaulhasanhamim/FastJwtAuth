namespace FastJwtAuth.Core.Tests;

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FastJwtAuth;
using FastJwtAuth.Core.Services;
using FastJwtAuth.Core.Tests.Entities;

public abstract class FastAuthServiceMock : FastAuthServiceBase<FastUser, FastRefreshToken, Guid>
{
    public FastAuthServiceMock(FastAuthOptions<FastUser, FastRefreshToken, Guid> authOptions, IFastUserValidator<FastUser> userValidator) 
        : base(authOptions, userValidator)
    {
    }

    public FastAuthServiceMock(FastAuthOptions<FastUser, FastRefreshToken, Guid> authOptions) 
        : base(authOptions, null!)
    {
    }

    public FastAuthServiceMock(IFastUserValidator<FastUser> userValidator) 
        : base(null!, userValidator)
    {
    }

    public FastAuthServiceMock() 
        : base(null!, null!)
    {
    }

    protected override Task addUserAsync(FastUser user, CancellationToken cancellationToken)
    {
        return AddUserAsyncMock(user, cancellationToken);
    }

    public abstract Task AddUserAsyncMock(FastUser user, CancellationToken cancellationToken);

    protected override Task<FastRefreshToken> createRefreshTokenAsync(FastUser user, CancellationToken cancellationToken)
    {
        return CreateRefreshTokenAsyncMock(user, cancellationToken);
    }

    public abstract Task<FastRefreshToken> CreateRefreshTokenAsyncMock(FastUser user, CancellationToken cancellationToken);

    protected override Task<bool> doesNormalizedEmailExistAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
        return DoesNormalizedEmailExistAsyncMock(normalizedEmail, cancellationToken);
    }

    public abstract Task<bool> DoesNormalizedEmailExistAsyncMock(string normalizedEmail, CancellationToken cancellationToken);

    protected override Task<(FastRefreshToken? RefreshToken, FastUser? User)> getRefreshTokenByIdAsync(string id, CancellationToken cancellationToken)
    {
        return GetRefreshTokenByIdAsyncMock(id, cancellationToken);
    }

    public abstract Task<(FastRefreshToken? RefreshToken, FastUser? User)> GetRefreshTokenByIdAsyncMock(string id, CancellationToken cancellationToken);

    protected override Task<FastUser?> getUserByNormalizedEmailAsync(string email, CancellationToken cancellationToken)
    {
        return GetUserByNormalizedEmailAsyncMock(email, cancellationToken);
    }

    public abstract Task<FastUser?> GetUserByNormalizedEmailAsyncMock(string email, CancellationToken cancellationToken);

    protected override Task removeRefreshTokenAsync(FastRefreshToken refreshTokenEntity, CancellationToken cancellationToken)
    {
        return RemoveRefreshTokenAsyncMock(refreshTokenEntity, cancellationToken);
    }

    public abstract Task RemoveRefreshTokenAsyncMock(FastRefreshToken refreshTokenEntity, CancellationToken cancellationToken);

    protected override Task updateUserAsync(FastUser user, CancellationToken cancellationToken)
    {
        return UpdateUserAsyncMock(user, cancellationToken);
    }

    public abstract Task UpdateUserAsyncMock(FastUser user, CancellationToken cancellationToken);
}