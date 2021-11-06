namespace FastJwtAuth.MongoDB;

public interface IFastAuthService<TUser> : IFastAuthService<TUser, FastRefreshToken<TUser>, string>
    where TUser : FastUser, new()
{
}

public interface IFastAuthService : IFastAuthService<FastUser, FastRefreshToken, string>
{

}
