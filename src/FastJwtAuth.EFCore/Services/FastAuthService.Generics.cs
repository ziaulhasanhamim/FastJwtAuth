namespace FastJwtAuth.EFCore.Services;

public class FastAuthService<TUser, TDbContext> : FastAuthService<TUser, FastRefreshToken<TUser>, TDbContext>, IFastAuthService<TUser>
    where TUser : FastUser, new()
    where TDbContext : DbContext
{
    public FastAuthService(
        TDbContext dbContext,
        EFCoreFastAuthOptions<TUser> authOptions,
        IFastUserValidator<TUser> userValidator)
        : base(dbContext, authOptions, userValidator)
    {
    }
}

public class FastAuthService<TDbContext> : FastAuthService<FastUser, FastRefreshToken, TDbContext>, IFastAuthService
    where TDbContext : DbContext
{
    public FastAuthService(
        TDbContext dbContext,
        EFCoreFastAuthOptions authOptions,
        IFastUserValidator<FastUser> userValidator)
        : base(dbContext, authOptions, userValidator)
    {
    }
}
