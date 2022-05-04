namespace FastJwtAuth;

public abstract class FastAuthOptions<TUser, TRefreshToken, TUserKey>
    where TUser : IFastUser<TUserKey>, new()
    where TRefreshToken : IFastRefreshToken<TUserKey>, new()
{
    public TokenCreationOptions? DefaultTokenCreationOptions { get; set; }

    /// <summary>
    /// false by default
    /// </summary>
    public bool UseRefreshToken { get; set; }

    /// <summary>
    /// This will be called when generating claims. You can add claims to the provided list
    /// </summary>
    public Action<List<Claim>, TUser>? GenerateClaims { get; set; }

    public void UseDefaultCredentials(ReadOnlySpan<char> secretKey)
    {
        DefaultTokenCreationOptions ??= new();
        DefaultTokenCreationOptions.UseDefaultCredentials(secretKey);
    }
}
