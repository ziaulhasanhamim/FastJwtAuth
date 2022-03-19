namespace FastJwtAuth.EFCore.Services;

public class FastAuthService<TUser, TRefreshToken> : FastAuthService<TUser, TRefreshToken, Guid>, IFastAuthService<TUser, TRefreshToken>
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
{
    public FastAuthService(IFastUserStore<TUser, TRefreshToken> userStore, EFCoreFastAuthOptions<TUser, TRefreshToken> authOptions)
        : base(userStore, authOptions)
    {
    }
}

public class FastAuthService<TUser> : FastAuthService<TUser, FastRefreshToken<TUser>>, IFastAuthService<TUser>
    where TUser : FastUser, new()
{
    public FastAuthService(IFastUserStore<TUser> userStore, EFCoreFastAuthOptions<TUser> authOptions)
        : base(userStore, authOptions)
    {
    }
}

public class FastAuthService : FastAuthService<FastUser, FastRefreshToken>, IFastAuthService
{
    public FastAuthService(IFastUserStore userStore, EFCoreFastAuthOptions authOptions)
        : base(userStore, authOptions)
    {
    }
}
