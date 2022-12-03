namespace FastJwtAuth.Core.Services;

public abstract partial class FastAuthServiceBase<TUser, TRefreshToken, TUserKey>
{
    public async Task<CreateUserResult> CreateUser(TUser user, string password, CancellationToken cancellationToken = default)
    {
        Guard.IsNotNull(password);
        if (_authOptions.UsernameState is FastFieldState.Required)
        {
            Guard.IsNotNull(user.Username);
        }
        if (_authOptions.EmailState is FastFieldState.Required)
        {
            Guard.IsNotNull(user.Email);
        }
        if (user is { Username: null, Email: null })
        {
            throw new ArgumentException("User can not have Username and Email both null");
        }
        if (user.Email is not null)
        {
            user.NormalizedEmail ??= NormalizeEmail(user.Email);
        }
        if (user.Username is not null)
        {
            user.NormalizedUsername ??= NormalizeEmail(user.Username);
        }

        var validationErrors = await ValidateUser(user, password, cancellationToken);

        if (validationErrors is not null)
        {
            return new(false, validationErrors);
        }

        user.PasswordHash ??= HashPassword(password);

        user.CreatedAt = DateTime.UtcNow;
        user.LastLogin = user.CreatedAt;

        await AddUser(user, cancellationToken);
        await CommitDbChanges(cancellationToken);
        return new(true, null);
    }
}