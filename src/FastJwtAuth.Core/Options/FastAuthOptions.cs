using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.Core.Options
{
    public class FastAuthOptions
    {
        public SigningCredentials? SigningCredentials { get; set; }

        public bool UseRefreshToken { get; set; }

        public TimeSpan AccessTokenLifeSpan { get; set; }

        public TimeSpan RefreshTokenLifeSpan { get; set; }

        /// <summary>
        /// This event is fired when generating claims. It Gives a List of previously created claims, user entity and service provider as parameter. New claims should be added to the List
        /// </summary>
        public event Action<List<Claim>, object, IServiceProvider>? OnClaimsGeneration;

        /// <summary>
        /// This event is fired when validating user. It Gives a user entity and service provider as parameter. if user is valid returns null else Dictionary of errors.
        /// </summary>
        public event Func<object, IServiceProvider, Dictionary<string, List<string>>>? OnUserValidate;
    }
}
