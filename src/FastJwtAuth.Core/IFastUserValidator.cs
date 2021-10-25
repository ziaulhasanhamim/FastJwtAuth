using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth
{
    /// <summary>
    /// Add a implementation of this interface in IOC container if you want to do custom validations
    /// </summary>
    public interface IFastUserValidator<TUser>
        where TUser : class
    {
        /// <summary>
        /// Validates the user
        /// </summary>
        /// <returns>A ValueTask of a two item Tuple. First element is bool which indicates if Validation is completed. If its true then no further validation would be performed. The second element is a dictionary containing Validation Errors. It should be null if no validation error is found</returns>
        ValueTask<(bool ValidationComplete, Dictionary<string, List<string>>? Errors)> ValidateAsync(TUser user);
    }
}
