namespace FastJwtAuth.Core.Services;

public abstract partial class FastAuthServiceBase<TUser, TRefreshToken, TUserKey>
{
    public async Task<CreateUserResult> CreateUser(TUser user, string password, CancellationToken cancellationToken = default)
    {
        Guard.IsNotNull(user.Email);
        Guard.IsNotNull(password);
        if (_authOptions.IsUsernameCompulsory)
        {
            Guard.IsNotNull(user.Username);
        }
        user.NormalizedEmail ??= NormalizeText(user.Email);
        if (user.Username is not null)
        {
            user.NormalizedUsername ??= NormalizeText(user.Username);
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