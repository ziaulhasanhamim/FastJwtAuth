namespace FastJwtAuth.EFCore;

using System.ComponentModel.DataAnnotations.Schema;

public class FastRefreshToken<TUser, TUserKey> : IFastRefreshToken<TUserKey>
    where TUser : FastUser<TUserKey>
{
    [Key]
    public string? Id { get; set; }

    [Required]
    public TUserKey? UserId { get; set; }

    [Required, ForeignKey(nameof(UserId))]
    public TUser? User { get; set; }

    [Required]
    public DateTime ExpiresAt { get; set; }
}

public class FastRefreshToken<TUser> : FastRefreshToken<TUser, Guid>
    where TUser : FastUser<Guid>, new()
{

}

public class FastRefreshToken : FastRefreshToken<FastUser>
{

}
