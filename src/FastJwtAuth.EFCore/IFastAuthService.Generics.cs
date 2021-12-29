namespace FastJwtAuth.EFCore;

public interface IFastAuthService<TUser> : IFastAuthService<TUser, FastRefreshToken<TUser>, Guid>
    where TUser : FastUser, new()
{
}

public interface IFastAuthService : IFastAuthService<FastUser, FastRefreshToken, Guid>
{

}
