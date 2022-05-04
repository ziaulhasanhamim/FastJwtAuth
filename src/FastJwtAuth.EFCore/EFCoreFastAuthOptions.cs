namespace FastJwtAuth.EFCore;

public class EFCoreFastAuthOptions<TUser, TRefreshToken> : FastAuthOptions<TUser, TRefreshToken, Guid>
    where TUser : FastUser, new()
    where TRefreshToken : FastRefreshToken<TUser>, new()
{
}

public class EFCoreFastAuthOptions<TUser> : EFCoreFastAuthOptions<TUser, FastRefreshToken<TUser>>
    where TUser : FastUser, new()
{
}

public class EFCoreFastAuthOptions : EFCoreFastAuthOptions<FastUser, FastRefreshToken>
{
}