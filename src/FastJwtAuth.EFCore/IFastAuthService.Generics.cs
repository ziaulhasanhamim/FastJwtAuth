namespace FastJwtAuth.EFCore;


public interface IFastAuthService<TUser> : IFastAuthService<TUser, FastRefreshToken<TUser>>
    where TUser : FastUser, new()
{
}

public interface IFastAuthService : IFastAuthService<FastUser, FastRefreshToken>
{

}
