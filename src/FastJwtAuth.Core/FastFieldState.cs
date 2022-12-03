namespace FastJwtAuth;

/// <summary>
/// Specifies What is state of a field in User Model
/// </summary>
public enum FastFieldState
{
    /// <summary>
    /// Specifies User won't have this field
    /// </summary>
    Nope,
    /// <summary>
    /// Specifies User can have this field but not required
    /// </summary>
    Has,
    /// <summary>
    /// Specifies User have to have this field
    /// </summary>
    Required
}
