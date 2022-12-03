namespace FastJwtAuth;

/// <summary>
/// User validation result
/// </summary>
/// <param name="ApplyDefaultValidations">If true there will be default validations applied after custom validation</param>
/// <param name="ErrorCodes">Codes to represent error type</param>
public readonly record struct FastUserValidationResult(
    bool ApplyDefaultValidations,
    List<string>? ErrorCodes);
