namespace FastJwtAuth.Core.Services;

public abstract partial class FastAuthServiceBase<TUser, TRefreshToken, TUserKey>
{
    protected virtual async ValueTask<List<string>?> ValidateUser(TUser user, string password, CancellationToken cancellationToken = default)
    {
        var (isValidationComplete, errors) = _userValidator switch
        {
            not null => await _userValidator.Validate(user, password),
            null => new(false, null)
        };
        if (isValidationComplete)
        {
            return errors;
        }
        errors = ValidatePassword(password, errors);
        errors = await ValidateEmail(user, errors, cancellationToken);
        if (user.Username is not null)
        {
            errors = await ValidateUsername(user, errors, cancellationToken);
        }
        return errors;
    }

    protected List<string>? ValidatePassword(string password, List<string>? errors) =>
        _authOptions switch
        {
            { PasswordMinLength: var minLength } when password.Length < minLength =>
                AddError(errors, FastAuthErrorCodes.PasswordVeryShort),

            { PasswordMaxLength: int maxLength } when password.Length < maxLength =>
                AddError(errors, FastAuthErrorCodes.PasswordVeryShort),

            _ => errors
        };

    protected async ValueTask<List<string>?> ValidateEmail(TUser user, List<string>? errors, CancellationToken cancellationToken) =>
        _emailValidator.IsValid(user.Email) switch
        {
            false => AddError(errors, FastAuthErrorCodes.InvalidEmailFormat),
            true when await DoesNormalizedEmailExist(user.NormalizedEmail!, cancellationToken) =>
                AddError(errors, FastAuthErrorCodes.DuplicateEmail),
            _ => errors
        };

    protected async ValueTask<List<string>?> ValidateUsername(TUser user, List<string>? errors, CancellationToken cancellationToken) =>
        _authOptions switch
        {
            { UsernameMinLength: var minLength } when user.Username!.Length < minLength =>
                AddError(errors, FastAuthErrorCodes.UsernameVeryShort),

            { UsernameMaxLength: int maxLength } when user.Username!.Length > maxLength =>
                AddError(errors, FastAuthErrorCodes.UsernameVeryLong),

            { } when !_usernameValidationRegex.IsMatch(user.Username) =>
                AddError(errors, FastAuthErrorCodes.InvalidUsernameFormat),

            { } when await DoesNormalizedUsernameExist(user.NormalizedUsername!, cancellationToken) =>
                AddError(errors, FastAuthErrorCodes.DuplicateUsername),

            _ => errors
        };

    static List<string> AddError(List<string>? errors, string err)
    {
        errors ??= new();
        errors.Add(err);
        return errors;
    }
}