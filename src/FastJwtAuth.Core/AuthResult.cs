namespace FastJwtAuth;

public interface IAuthResult<TUser>
{
}

public record SuccessAuthResult<TUser>(
    string AccessToken,
    DateTimeOffset AccessTokenExpiresAt,
    string? RefreshToken,
    DateTimeOffset? RefreshTokenExpiresAt,
    TUser User)
    : IAuthResult<TUser>;


public enum AuthErrorType
{
    DuplicateEmail,
    InvalidEmailFormat,

    /// <summary>Wrong Credential for login</summary>
    WrongEmail,
    
    /// <summary>Wrong Credential for login</summary>
    WrongPassword,
    PasswordVeryShort,
    InvalidRefreshToken,
    ExpiredRefreshToken,
}

public record FailureAuthResult<TUser>(List<AuthErrorType> Errors) : IAuthResult<TUser>;
