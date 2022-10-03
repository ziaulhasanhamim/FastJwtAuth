namespace FastJwtAuth.Core.Services;

using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;

public abstract partial class FastAuthServiceBase<TUser, TRefreshToken, TUserKey> :
    IFastAuthService<TUser, TRefreshToken, TUserKey>
    where TUser : class, IFastUser<TUserKey>, new()
    where TRefreshToken : class, IFastRefreshToken<TUserKey>, new()
{
    protected readonly FastAuthOptions<TUser, TRefreshToken, TUserKey> _authOptions;
    protected readonly IFastUserValidator<TUser>? _userValidator;

    public const string UsernameValidationRegex = @"^[a-zA-Z0-9]([-._](?![-._])|[a-zA-Z0-9])*[a-zA-Z0-9]$";

    private static readonly Regex _usernameValidationRegex = new(UsernameValidationRegex, RegexOptions.Compiled);

    private readonly static EmailAddressAttribute _emailValidator = new();
    private readonly static JwtSecurityTokenHandler _jwtSecurityTokenHandler = new();

    protected FastAuthServiceBase(FastAuthOptions<TUser, TRefreshToken, TUserKey> authOptions, IFastUserValidator<TUser>? userValidator)
    {
        _authOptions = authOptions;
        _userValidator = userValidator;
    }

    private async Task<AuthResult<TUser>.Success> GenerateTokens(TUser user, TokenCreationOptions tokenCreationOptions, CancellationToken cancellationToken)
    {
        var refreshToken = _authOptions.UseRefreshToken switch
        {
            true => await CreateRefreshToken(user, tokenCreationOptions, cancellationToken),
            false => null
        };

        var claims = GetClaimsForUser(user);
        JwtSecurityToken securityToken = new(
            claims: claims,
            expires: DateTime.UtcNow.Add(tokenCreationOptions.AccessTokenLifeSpan),
            signingCredentials: tokenCreationOptions.SigningCredentials,
            issuer: tokenCreationOptions.Issuer,
            audience: tokenCreationOptions.Audience);
        var accessToken = _jwtSecurityTokenHandler.WriteToken(securityToken);
        return new(
            accessToken,
            securityToken.ValidTo,
            refreshToken?.Id,
            refreshToken?.ExpiresAt,
            user);
    }

    public virtual bool VerifyPassword(string rawPassword, string hashedPassword) =>
        BCrypt.Net.BCrypt.Verify(rawPassword, hashedPassword);

    public virtual string HashPassword(string password) => BCrypt.Net.BCrypt.HashPassword(password);

    public virtual List<Claim> GetClaimsForUser(TUser user)
    {
        List<Claim> claims = new()
        {
            new(JwtRegisteredClaimNames.Sub, user.Id!.ToString()!),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(nameof(IFastUser<Guid>.CreatedAt), user.CreatedAt.ToString()!)
        };
        if (user.Username is not null)
        {
            claims.Add(new(JwtRegisteredClaimNames.UniqueName, user.Username));
        }
        _authOptions.OnClaimsGeneration?.Invoke(claims, user);
        return claims;
    }

    public virtual string NormalizeText(string text) => text.Normalize().ToUpperInvariant();
}
