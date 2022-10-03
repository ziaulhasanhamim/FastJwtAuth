namespace FastJwtAuth.Core.Tests;

using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using FastJwtAuth;
using FastJwtAuth.Core.Services;
using FastJwtAuth.Core.Tests.Entities;

public abstract class FastAuthServiceMock : FastAuthServiceBase<FastUser, FastRefreshToken, Guid>
{
    protected FastAuthServiceMock(FastAuthOptions<FastUser, FastRefreshToken, Guid> authOptions, IFastUserValidator<FastUser> userValidator)
        : base(authOptions, userValidator)
    {
    }

    protected FastAuthServiceMock(FastAuthOptions<FastUser, FastRefreshToken, Guid> authOptions)
        : base(authOptions, null)
    {
    }

    protected FastAuthServiceMock(IFastUserValidator<FastUser> userValidator)
        : base(null!, userValidator)
    {
    }

    protected FastAuthServiceMock()
        : base(null!, null)
    {
    }

    public sealed override List<Claim> GetClaimsForUser(FastUser user) =>
        base.GetClaimsForUser(user);

    protected sealed override ValueTask<List<string>?> ValidateUser(FastUser user, string password, CancellationToken cancellationToken = default) =>
        base.ValidateUser(user, password, cancellationToken);

    public sealed override string NormalizeText(string text) => base.NormalizeText(text);

    protected override Task AddUser(FastUser user, CancellationToken cancellationToken)
    {
        return AddUserMock(user, cancellationToken);
    }

    public abstract Task AddUserMock(FastUser user, CancellationToken cancellationToken);

    protected override ValueTask<FastRefreshToken> CreateRefreshToken(FastUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken)
    {
        return CreateRefreshTokenMock(user, cancellationToken);
    }

    public abstract ValueTask<FastRefreshToken> CreateRefreshTokenMock(FastUser user, CancellationToken cancellationToken);

    protected override Task<bool> DoesNormalizedEmailExist(string normalizedEmail, CancellationToken cancellationToken)
    {
        return DoesNormalizedEmailExistMock(normalizedEmail, cancellationToken);
    }

    public abstract Task<bool> DoesNormalizedEmailExistMock(string normalizedEmail, CancellationToken cancellationToken);

    protected override Task<bool> DoesNormalizedUsernameExist(string normalizedUsername, CancellationToken cancellationToken)
    {
        return DoesNormalizedUsernameExistMock(normalizedUsername, cancellationToken);
    }

    public abstract Task<bool> DoesNormalizedUsernameExistMock(string normalizedUsername, CancellationToken cancellationToken);

    protected override Task<(FastRefreshToken? RefreshToken, FastUser? User)> GetRefreshTokenById(string id, CancellationToken cancellationToken)
    {
        return GetRefreshTokenByIdMock(id, cancellationToken);
    }

    public abstract Task<(FastRefreshToken? RefreshToken, FastUser? User)> GetRefreshTokenByIdMock(string id, CancellationToken cancellationToken);

    protected override Task<FastUser?> GetUserByNormalizedEmail(string email, CancellationToken cancellationToken)
    {
        return GetUserByNormalizedEmailMock(email, cancellationToken);
    }

    public abstract Task<FastUser?> GetUserByNormalizedEmailMock(string email, CancellationToken cancellationToken);

    protected override Task RemoveRefreshToken(FastRefreshToken refreshTokenEntity, CancellationToken cancellationToken)
    {
        return RemoveRefreshTokenMock(refreshTokenEntity, cancellationToken);
    }

    public abstract Task RemoveRefreshTokenMock(FastRefreshToken refreshTokenEntity, CancellationToken cancellationToken);

    protected override Task UpdateUserLastLogin(FastUser user, CancellationToken cancellationToken)
    {
        return UpdateUserLastLoginMock(user, cancellationToken);
    }

    public abstract Task UpdateUserLastLoginMock(FastUser user, CancellationToken cancellationToken);

    protected override Task CommitDbChanges(CancellationToken cancellationToken)
    {
        return CommitDbChangesMock(cancellationToken);
    }

    public abstract Task CommitDbChangesMock(CancellationToken cancellationToken);
}