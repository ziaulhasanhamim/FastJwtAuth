namespace FastJwtAuth;

public static class FastAuthErrorCodes
{
    public const string DuplicateEmail = nameof(DuplicateEmail);

    public const string InvalidEmailFormat = nameof(InvalidEmailFormat);

    public const string WrongEmail = nameof(WrongEmail);

    public const string WrongPassword = nameof(WrongPassword);

    public const string PasswordVeryShort = nameof(PasswordVeryShort);

    public const string PasswordVeryLong = nameof(PasswordVeryLong);

    public const string InvalidRefreshToken = nameof(InvalidRefreshToken);

    public const string ExpiredRefreshToken = nameof(ExpiredRefreshToken);

    public const string InvalidUsernameFormat = nameof(InvalidUsernameFormat);

    public const string UsernameVeryShort = nameof(UsernameVeryShort);

    public const string UsernameVeryLong = nameof(UsernameVeryLong);

    public const string DuplicateUsername = nameof(DuplicateUsername);

    public const string InvalidNumberFormat = nameof(InvalidNumberFormat);

    public const string DuplicateNumber = nameof(DuplicateNumber);

    /// <summary>Returned if the provided user don't have none of these Email, PhoneNumber or Username</summary>
    public const string IdentifierNotFound = nameof(IdentifierNotFound);
}
