namespace FastJwtAuth.MongoDB;

using Microsoft.Extensions.DependencyInjection;


public class MongoFastAuthBuilder
{
    public IServiceCollection? Services { get; set; }

    public MongoFastAuthOptions? AuthOptions { get; set; }

    public Type? UserType { get; set; }

    public Type? RefreshTokenType { get; set; }
}
