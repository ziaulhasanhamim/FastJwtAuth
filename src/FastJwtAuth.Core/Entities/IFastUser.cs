namespace FastJwtAuth.Core.Entities;

public interface IFastUser<TKey>
{
    public TKey? Id { get; set; }

    public string? Email { get; set; }

    public string? NormalizedEmail { get; set; }

    public string? PasswordHash { get; set; }

    /// <summary>
    /// User Creation date. Generally Stored in utc
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last time user logged in. Generally Stored in utc
    /// </summary>
    public DateTime? LastLogin { get; set; }
}
