namespace FastJwtAuth.MongoDB.Services;


public class FastUserStore<TUser> : FastUserStore<TUser, FastRefreshToken<TUser>>, IFastUserStore<TUser>
    where TUser : FastUser, new()
{
    public FastUserStore(
        MongoFastAuthOptions<TUser> authOptions, 
        IServiceProvider sp, 
        IFastUserValidator<TUser>? userValidator = null) 
        : base(authOptions, sp, userValidator)
    {
    }
}

public class FastUserStore : FastUserStore<FastUser, FastRefreshToken>, IFastUserStore
{
    public FastUserStore(
        MongoFastAuthOptions authOptions, 
        IServiceProvider sp, 
        IFastUserValidator<FastUser>? userValidator = null) 
        : base(authOptions, sp, userValidator)
    {
    }
}