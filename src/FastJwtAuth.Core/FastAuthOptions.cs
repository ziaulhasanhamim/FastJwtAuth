using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth
{
    public class FastAuthOptions
    {
        public SigningCredentials? DefaultSigningCredentials { get; set; }

        public bool UseRefreshToken { get; set; }

        /// <summary>
        /// Default to 15 days
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

        /// <summary>
        /// This event is fired when generating claims. It Gives a List of previously created claims, user entity and service provider as parameter. New claims should be added to the List
        /// </summary>
        public Action<List<Claim>, object>? OnClaimsGeneration { get; set; }

        /// <summary>
        /// This event is fired when validating user. It Gives a user entity and a db accessor(DbContext for ef core) as parameters. if user is valid returns null else Dictionary of errors.
        /// </summary>
        public Func<object, object, Task<Dictionary<string, List<string>>>>? OnUserValidate { get; set; }
    }
}
