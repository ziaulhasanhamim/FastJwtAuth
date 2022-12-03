using Microsoft.IdentityModel.Tokens;

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
    /// This will be called when generating claims. You can add, remove or modify claims
    /// </summary>
    public Action<List<Claim>, TUser>? OnClaimsGeneration { get; set; }

    /// <summary>
    /// Defaults to <see cref="FastFieldState.Nope"/>
    /// </summary>
    public FastFieldState UsernameState { get; set; }

    /// <summary>
    /// Defaults to <see cref="FastFieldState.Required"/>
    /// </summary>
    public FastFieldState EmailState { get; set; } = FastFieldState.Required;

    /// <summary>
    /// Defaults to 8
    /// </summary>
    public int PasswordMinLength { get; set; } = 8;

    public int? PasswordMaxLength { get; set; }

    /// <summary>
    /// Defaults to 5
    /// </summary>
    public int UsernameMinLength { get; set; } = 5;

    public int? UsernameMaxLength { get; set; }

    /// <summary>
    /// Create and set <see cref="TokenCreationOptions.SigningCredentials"/> with <paramref name="secretKey"/> and <see cref="SecurityAlgorithms.HmacSha256"/> algorithm
    /// </summary>
    public void UseDefaultCredentials(ReadOnlySpan<char> secretKey)
    {
        DefaultTokenCreationOptions ??= new();
        DefaultTokenCreationOptions.UseSymmetricCredentials(secretKey);
    }
}