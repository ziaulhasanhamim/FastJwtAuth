namespace FastJwtAuth;

public static class FastAuthErrorCodes
{
    public const string DuplicateEmail = nameof(DuplicateEmail);

    public const string InvalidEmailFormat = nameof(InvalidEmailFormat);

    public const string WrongEmail = nameof(WrongEmail);
    
    public const string WrongPassword = nameof(WrongPassword);

    public const string PasswordVeryShort = nameof(PasswordVeryShort);

    public const string InvalidRefreshToken = nameof(InvalidRefreshToken);

    public const string ExpiredRefreshToken = nameof(ExpiredRefreshToken);
}
