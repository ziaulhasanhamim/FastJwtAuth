using FastJwtAuth.Core.Services;
using System;

namespace FastJwtAuth.MongoDB
{

    public interface IFastAuthService<TUser> : IFastAuthService<TUser, FastRefreshToken<TUser>>
        where TUser : FastUser, new()
    {
    }

    public interface IFastAuthService : IFastAuthService<FastUser, FastRefreshToken>
    {

    }
}
