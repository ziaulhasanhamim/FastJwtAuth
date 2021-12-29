namespace FastJwtAuth;

public interface AuthResult<TUser>
{
    public record Failure(List<string> ErrorCodes) : AuthResult<TUser>;

    public record Success(
        string AccessToken,
        DateTimeOffset AccessTokenExpiresAt,
        string? RefreshToken,
        DateTimeOffset? RefreshTokenExpiresAt,
        TUser User)
        : AuthResult<TUser>;
}
