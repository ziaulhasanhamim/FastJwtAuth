using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace FastJwtAuth.MongoDB.Tests.Services
{
    public class TestUserValidator : IFastUserValidator<FastUser>
    {
        private readonly Func<FastUser, (bool ValidationComplete, Dictionary<string, List<string>>? Errors)> _func;

        public TestUserValidator(Func<FastUser, (bool ValidationComplete, Dictionary<string, List<string>>? Errors)> func)
        {
            _func = func;
        }

        public ValueTask<(bool ValidationComplete, Dictionary<string, List<string>>? Errors)> ValidateAsync(FastUser user)
        {
            return ValueTask.FromResult(_func(user));
        }
    }
}