namespace FastJwtAuth.EFCore.Tests.Services;

public class TestUserValidator : IFastUserValidator<FastUser>
{
    private readonly Func<FastUser, string, (bool ValidationComplete, List<string>? ErrorCodes)> _func;

    public TestUserValidator(Func<FastUser, string, (bool ValidationComplete, List<string>? ErrorCodes)> func)
    {
        _func = func;
    }

    public ValueTask<(bool ValidationComplete, List<string>? ErrorCodes)> ValidateAsync(FastUser user, string password)
    {
        return ValueTask.FromResult(_func(user, password));
    }
}
