namespace FastJwtAuth.Core.Entities;
public interface IFastRefreshToken<TUserKey>
{
    public string? Id { get; set; }

    public TUserKey? UserId { get; set; }

    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// ExpireDate for RefreshToken. Generally Stored in utc
    /// </summary>
    public DateTime ExpiresAt { get; set; }
}
