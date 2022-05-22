namespace FastJwtAuth.EFCore;

public class FastUser : IFastUser<Guid>
{
    public Guid Id { get; set; }

    public string? Email { get; set; }

    public string? NormalizedEmail { get; set; }

    public string? Username { get; set; }

    public string? NormalizedUsername { get; set; }

    public string? PasswordHash { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime? LastLogin { get; set; }
}