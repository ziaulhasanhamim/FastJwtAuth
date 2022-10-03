namespace FastJwtAuth;

using System.Text;
using Microsoft.IdentityModel.Tokens;

public sealed class TokenCreationOptions
{
    public SigningCredentials? SigningCredentials { get; set; }

    /// <summary>
    /// Default to 15 miniutes
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

    public string? Issuer { get; set; }

    public string? Audience { get; set; }

    /// <summary>
    /// Create and set <see cref="SigningCredentials"/> with <paramref name="secretKey"/> and <see cref="SecurityAlgorithms.HmacSha256"/> algorithm
    /// </summary>
    public TokenCreationOptions UseSymmetricCredentials(ReadOnlySpan<char> secretKey)
    {
        if (SigningCredentials is not null)
        {
            throw new NotSupportedException("SigningCredentials already has a value");
        }
        var bytesCount = Encoding.Unicode.GetByteCount(secretKey);
        var secretBytes = new byte[bytesCount];

        var byteRecv = Encoding.Unicode.GetBytes(secretKey, secretBytes);

        Debug.Assert(bytesCount == byteRecv);

        SymmetricSecurityKey securityKey = new(secretBytes);
        SigningCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);
        return this;
    }
}
