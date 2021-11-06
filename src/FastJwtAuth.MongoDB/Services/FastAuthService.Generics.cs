namespace FastJwtAuth.MongoDB.Services;

public class FastAuthService<TUser> : FastAuthService<TUser, FastRefreshToken<TUser>, string>, IFastAuthService<TUser>
    where TUser : FastUser, new()
{
    public FastAuthService(IFastUserStore<TUser, FastRefreshToken<TUser>, string> userStore, FastAuthOptions authOptions)
        : base(userStore, authOptions)
    {
    }
}

public class FastAuthService : FastAuthService<FastUser, FastRefreshToken, string>, IFastAuthService
{
    public FastAuthService(IFastUserStore<FastUser, FastRefreshToken, string> userStore, FastAuthOptions authOptions)
        : base(userStore, authOptions)
    {
    }
}
