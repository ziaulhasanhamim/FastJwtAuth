namespace FastJwtAuth;

public readonly record struct CreateUserResult(
    bool Success,
    List<string>? ErrorCodes);
