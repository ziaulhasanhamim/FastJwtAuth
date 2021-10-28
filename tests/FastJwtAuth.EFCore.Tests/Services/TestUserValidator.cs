using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace FastJwtAuth.EFCore.Tests.Services
{
    public class TestUserValidator : IFastUserValidator<FastUser>
    {
        private readonly Func<FastUser, string, (bool ValidationComplete, Dictionary<string, List<string>>? Errors)> _func;

        public TestUserValidator(Func<FastUser, string, (bool ValidationComplete, Dictionary<string, List<string>>? Errors)> func)
        {
            _func = func;
        }

        public ValueTask<(bool ValidationComplete, Dictionary<string, List<string>>? Errors)> ValidateAsync(FastUser user, string password)
        {
            return ValueTask.FromResult(_func(user, password));
        }
    }
}