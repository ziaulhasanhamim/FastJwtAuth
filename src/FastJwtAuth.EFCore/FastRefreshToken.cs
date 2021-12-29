namespace FastJwtAuth.EFCore;

using System.ComponentModel.DataAnnotations.Schema;

public class FastRefreshToken<TUser> : IFastRefreshToken<Guid>
    where TUser : FastUser
{
    [Key]
    public string? Id { get; set; }

    [Required]
    public Guid UserId { get; set; }

    [Required, ForeignKey(nameof(UserId))]
    public TUser? User { get; set; }

    [Required]
    public DateTime ExpiresAt { get; set; }
}

public class FastRefreshToken : FastRefreshToken<FastUser>
{

}
