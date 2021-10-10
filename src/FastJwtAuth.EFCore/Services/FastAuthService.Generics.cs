using FastJwtAuth.Core.Services;
using System;

namespace FastJwtAuth.EFCore.Services
{

    public class FastAuthService<TUser> : FastAuthService<TUser, FastRefreshToken<TUser>>, IFastAuthService<TUser>
        where TUser : FastUser, new()
    {
        public FastAuthService(IFastUserStore<TUser, FastRefreshToken<TUser>> userStore, FastAuthOptions authOptions)
            : base(userStore, authOptions)
        {
        }
    }

    public class FastAuthService : FastAuthService<FastUser, FastRefreshToken>, IFastAuthService
    {
        public FastAuthService(IFastUserStore<FastUser, FastRefreshToken> userStore, FastAuthOptions authOptions)
            : base(userStore, authOptions)
        {
        }
    }
}
