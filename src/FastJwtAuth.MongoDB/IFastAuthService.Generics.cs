namespace FastJwtAuth.MongoDB;

public interface IFastAuthService<TUser, TRefreshToken> : IFastAuthService<TUser, TRefreshToken, string>
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
{
}

public interface IFastAuthService<TUser> : IFastAuthService<TUser, FastRefreshToken<TUser>>
    where TUser : FastUser, new()
{
}

public interface IFastAuthService : IFastAuthService<FastUser, FastRefreshToken>
{

}
