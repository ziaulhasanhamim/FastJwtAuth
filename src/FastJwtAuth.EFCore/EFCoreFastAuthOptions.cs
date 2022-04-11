namespace FastJwtAuth.EFCore;

public class EFCoreFastAuthOptions<TUser, TRefreshToken> : FastAuthOptions<TUser, TRefreshToken, Guid>
    where TUser : FastUser
    where TRefreshToken : FastRefreshToken<TUser>
{
}

public class EFCoreFastAuthOptions<TUser> : EFCoreFastAuthOptions<TUser, FastRefreshToken<TUser>>
    where TUser : FastUser
{
}

public class EFCoreFastAuthOptions : EFCoreFastAuthOptions<FastUser, FastRefreshToken>
{
}