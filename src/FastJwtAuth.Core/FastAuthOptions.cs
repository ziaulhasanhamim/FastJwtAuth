﻿namespace FastJwtAuth;

using Microsoft.IdentityModel.Tokens;

public abstract class FastAuthOptions<TUser, TRefreshToken, TUserKey>
    where TUser : IFastUser<TUserKey>
    where TRefreshToken : IFastRefreshToken<TUserKey>
{
    public SigningCredentials? DefaultSigningCredentials { get; set; }

    public bool UseRefreshToken { get; set; }

    /// <summary>
    /// Default to 15 days
    /// </summary>
    public TimeSpan AccessTokenLifeSpan { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Default to 15 days
    /// </summary>
    public TimeSpan RefreshTokenLifeSpan { get; set; } = TimeSpan.FromDays(15);

    /// <summary>
    /// Number of bytes to generate for refresh token. Default to 32
    /// </summary>
    public int RefreshTokenBytesLength { get; set; } = 32;

    /// <summary>
    /// This event is fired when generating claims. It Gives a List of previously created claims, user entity and service provider as parameter. New claims should be added to the List
    /// </summary>
    public Action<List<Claim>, TUser>? OnClaimsGeneration { get; set; }
}
