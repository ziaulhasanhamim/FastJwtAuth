namespace FastJwtAuth.MongoDB;

using global::MongoDB.Bson.Serialization.Attributes;

public class FastUser : IFastUser<string>
{

    [BsonId, BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public string? Email { get; set; }

    public string? NormalizedEmail { get; set; }

    public string? PasswordHash { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime? LastLogin { get; set; }
}
