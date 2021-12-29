namespace FastJwtAuth.EFCore.Services;

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
