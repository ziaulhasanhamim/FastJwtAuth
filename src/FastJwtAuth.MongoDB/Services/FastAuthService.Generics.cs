namespace FastJwtAuth.MongoDB.Services;

[Open]
public class FastAuthService<TUser> : FastAuthService<TUser, FastRefreshToken<TUser>>, IFastAuthService<TUser>
    where TUser : FastUser, new()
{
    public FastAuthService(
        MongoFastAuthOptions<TUser> authOptions,
        IServiceProvider sp,
        IFastUserValidator<TUser>? userValidator = null)
        : base(authOptions, sp, userValidator)
    {
    }
}

[Open]
public class FastAuthService : FastAuthService<FastUser, FastRefreshToken>, IFastAuthService
{
    public FastAuthService(
        MongoFastAuthOptions authOptions,
        IServiceProvider sp,
        IFastUserValidator<FastUser>? userValidator = null)
        : base(authOptions, sp, userValidator)
    {
    }
}
