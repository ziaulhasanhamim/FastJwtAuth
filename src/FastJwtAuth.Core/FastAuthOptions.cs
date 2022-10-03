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
    public Action<List<Claim>, TUser>? OnClaimsGeneration { get; set; }

    private bool _hasUsername;

    public bool HasUsername
    {
        get => _hasUsername;
        set
        {
            if (!value)
            {
                _isUsernameCompulsory = false;
            }
            _hasUsername = value;
        }
    }

    private bool _isUsernameCompulsory;

    public bool IsUsernameCompulsory
    {
        get => _isUsernameCompulsory;
        set
        {
            if (value)
            {
                Guard.IsTrue(HasUsername);
            }
            _isUsernameCompulsory = value;
        }
    }

    public int PasswordMinLength { get; set; } = 8;

    public int? PasswordMaxLength { get; set; }

    public int UsernameMinLength { get; set; } = 5;

    public int? UsernameMaxLength { get; set; }

    public void UseDefaultCredentials(ReadOnlySpan<char> secretKey)
    {
        DefaultTokenCreationOptions ??= new();
        DefaultTokenCreationOptions.UseSymmetricCredentials(secretKey);
    }
}
