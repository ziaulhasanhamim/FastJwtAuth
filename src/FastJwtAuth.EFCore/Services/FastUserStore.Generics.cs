namespace FastJwtAuth.EFCore.Services;


public class FastUserStore<TUser, TDbContext> : FastUserStore<TUser, FastRefreshToken<TUser>, TDbContext>, IFastUserStore<TUser>
    where TUser : FastUser, new()
    where TDbContext : DbContext
{
    public FastUserStore(TDbContext dbContext, EFCoreFastAuthOptions<TUser> authOptions, IFastUserValidator<TUser>? userValidator = null) 
        : base(dbContext, authOptions, userValidator)
    {
    }
}

public class FastUserStore<TDbContext> : FastUserStore<FastUser, FastRefreshToken, TDbContext>, IFastUserStore
    where TDbContext : DbContext
{
    public FastUserStore(TDbContext dbContext, EFCoreFastAuthOptions authOptions, IFastUserValidator<FastUser>? userValidator = null) 
        : base(dbContext, authOptions, userValidator)
    {
    }
}