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

    protected override Task addUser(FastUser user, CancellationToken cancellationToken)
    {
        return AddUserMock(user, cancellationToken);
    }

    public abstract Task AddUserMock(FastUser user, CancellationToken cancellationToken);

    protected override async ValueTask<FastRefreshToken> createRefreshToken(FastUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken)
    {
        return await CreateRefreshTokenMock(user, cancellationToken);
    }

    public abstract Task<FastRefreshToken> CreateRefreshTokenMock(FastUser user, CancellationToken cancellationToken);

    protected override Task<bool> doesNormalizedEmailExist(string normalizedEmail, CancellationToken cancellationToken)
    {
        return DoesNormalizedEmailExistMock(normalizedEmail, cancellationToken);
    }

    public abstract Task<bool> DoesNormalizedEmailExistMock(string normalizedEmail, CancellationToken cancellationToken);

    protected override Task<bool> doesNormalizedUsernameExist(string normalizedUsername, CancellationToken cancellationToken)
    {
        return DoesNormalizedUsernameExistMock(normalizedUsername, cancellationToken);
    }

    public abstract Task<bool> DoesNormalizedUsernameExistMock(string normalizedUsername, CancellationToken cancellationToken);

    protected override Task<(FastRefreshToken? RefreshToken, FastUser? User)> getRefreshTokenById(string id, CancellationToken cancellationToken)
    {
        return GetRefreshTokenByIdMock(id, cancellationToken);
    }

    public abstract Task<(FastRefreshToken? RefreshToken, FastUser? User)> GetRefreshTokenByIdMock(string id, CancellationToken cancellationToken);

    protected override Task<FastUser?> getUserByNormalizedEmail(string email, CancellationToken cancellationToken)
    {
        return GetUserByNormalizedEmailMock(email, cancellationToken);
    }

    public abstract Task<FastUser?> GetUserByNormalizedEmailMock(string email, CancellationToken cancellationToken);

    protected override Task removeRefreshToken(FastRefreshToken refreshTokenEntity, CancellationToken cancellationToken)
    {
        return RemoveRefreshTokenMock(refreshTokenEntity, cancellationToken);
    }

    public abstract Task RemoveRefreshTokenMock(FastRefreshToken refreshTokenEntity, CancellationToken cancellationToken);

    protected override Task updateUserLastLogin(FastUser user, CancellationToken cancellationToken)
    {
        return UpdateUserLastLoginMock(user, cancellationToken);
    }

    public abstract Task UpdateUserLastLoginMock(FastUser user, CancellationToken cancellationToken);

    protected override Task commitDbChanges(CancellationToken cancellationToken)
    {
        return CommitDbChangesMock(cancellationToken);
    }

    public abstract Task CommitDbChangesMock(CancellationToken cancellationToken);
}