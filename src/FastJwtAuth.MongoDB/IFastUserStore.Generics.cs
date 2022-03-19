namespace FastJwtAuth.MongoDB;

public interface IFastUserStore<TUser, TRefreshToken> : IFastUserStore<TUser, TRefreshToken, string>
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
{
}

public interface IFastUserStore<TUser> : IFastUserStore<TUser, FastRefreshToken<TUser>>
    where TUser : FastUser, new()
{
}

public interface IFastUserStore : IFastUserStore<FastUser, FastRefreshToken>
{
}