namespace FastJwtAuth.EFCore.Services;

public class FastAuthService<TUser, TUserKey> : FastAuthService<TUser, FastRefreshToken<TUser, TUserKey>, TUserKey>, IFastAuthService<TUser, TUserKey>
    where TUser : FastUser<TUserKey>, new()
{
    public FastAuthService(IFastUserStore<TUser, FastRefreshToken<TUser, TUserKey>, TUserKey> userStore, FastAuthOptions authOptions)
        : base(userStore, authOptions)
    {
    }
}

public class FastAuthService<TUser> : FastAuthService<TUser, FastRefreshToken<TUser>, Guid>, IFastAuthService<TUser>
    where TUser : FastUser, new()
{
    public FastAuthService(IFastUserStore<TUser, FastRefreshToken<TUser>, Guid> userStore, FastAuthOptions authOptions)
        : base(userStore, authOptions)
    {
    }
}

public class FastAuthService : FastAuthService<FastUser, FastRefreshToken, Guid>, IFastAuthService
{
    public FastAuthService(IFastUserStore<FastUser, FastRefreshToken, Guid> userStore, FastAuthOptions authOptions)
        : base(userStore, authOptions)
    {
    }
}
