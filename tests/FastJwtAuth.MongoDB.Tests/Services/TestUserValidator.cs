using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace FastJwtAuth.MongoDB.Tests.Services
{
    public class TestUserValidator : IFastUserValidator<FastUser>
    {
        private readonly Func<FastUser, string, (bool ValidationComplete, List<AuthErrorType>? Erros)> _func;

        public TestUserValidator(Func<FastUser, string, (bool ValidationComplete, List<AuthErrorType>? Erros)> func)
        {
            _func = func;
        }

        public ValueTask<(bool ValidationComplete, List<AuthErrorType>? Errors)> ValidateAsync(FastUser user, string password)
        {
            return ValueTask.FromResult(_func(user, password));
        }
    }
}