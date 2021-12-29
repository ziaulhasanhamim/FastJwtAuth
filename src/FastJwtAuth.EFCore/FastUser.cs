namespace FastJwtAuth.EFCore;


[Index(nameof(NormalizedEmail))]
public class FastUser : IFastUser<Guid>
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public string? Email { get; set; }

    [Required]
    public string? NormalizedEmail { get; set; }

    [Required]
    public string? PasswordHash { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; }

    public DateTime? LastLogin { get; set; }

}