namespace FastJwtAuth.Core.Entities;

public interface IFastUser<TKey>
{
    TKey? Id { get; set; }

    string? Email { get; set; }

    string? NormalizedEmail { get; set; }

    string? Username { get; set; }

    string? NormalizedUsername { get; set; }

    string? PasswordHash { get; set; }

    /// <summary>
    /// User Creation date. Generally Stored in utc
    /// </summary>
    DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last time user logged in. Generally Stored in utc
    /// </summary>
    DateTime? LastLogin { get; set; }
}
