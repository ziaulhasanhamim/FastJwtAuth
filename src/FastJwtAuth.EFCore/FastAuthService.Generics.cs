using FastJwtAuth.Core.Services;
using FastJwtAuth.EFCore.Entities;
using System;

namespace FastJwtAuth
{
    public interface IFastAuthService<TUser> : IFastAuthService<TUser, FastRefreshToken<TUser>>
        where TUser : FastUser
    {

    }

    public class FastAuthService<TUser> : FastAuthService<TUser, FastRefreshToken<TUser>>, IFastAuthService<TUser>
        where TUser : FastUser
    {
        public FastAuthService(IFastUserStore<TUser, FastRefreshToken<TUser>> userStore, FastAuthOptions authOptions) 
            : base(userStore, authOptions)
        {
        }
    }

    public interface IFastAuthService : IFastAuthService<FastUser, FastRefreshToken>
    {

    }

    public class FastAuthService : FastAuthService<FastUser, FastRefreshToken>, IFastAuthService
    {
        public FastAuthService(IFastUserStore<FastUser, FastRefreshToken> userStore, FastAuthOptions authOptions) 
            : base(userStore, authOptions)
        {
        }
    }
}
