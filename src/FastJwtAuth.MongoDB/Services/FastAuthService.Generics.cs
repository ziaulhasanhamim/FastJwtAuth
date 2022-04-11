namespace FastJwtAuth.MongoDB.Services;

public class FastAuthService<TUser, TRefreshToken> : FastAuthServiceBase<TUser, TRefreshToken, string>, IFastAuthService<TUser, TRefreshToken>
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
{
    public FastAuthService(IFastUserStore<TUser, TRefreshToken> userStore, MongoFastAuthOptions<TUser, TRefreshToken> authOptions)
        : base(userStore, authOptions)
    {
    }
}

public class FastAuthService<TUser> : FastAuthService<TUser, FastRefreshToken<TUser>>, IFastAuthService<TUser>
    where TUser : FastUser, new()
{
    public FastAuthService(IFastUserStore<TUser> userStore, MongoFastAuthOptions<TUser> authOptions)
        : base(userStore, authOptions)
    {
    }
}

public class FastAuthService : FastAuthService<FastUser, FastRefreshToken>, IFastAuthService
{
    public FastAuthService(IFastUserStore userStore, MongoFastAuthOptions authOptions)
        : base(userStore, authOptions)
    {
    }
}
