using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth
{
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

    public record FailureAuthResult<TUser>(
        string Title,
        Dictionary<string, List<string>>? Errors)
        : IAuthResult<TUser>;
}
