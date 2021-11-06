namespace FastJwtAuth.MongoDB;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

public static class Extensions
{
    public static Task CreateFastUserIndexes<TUser>(this IMongoCollection<TUser> usersCollection, CancellationToken cancellationToken = default)
        where TUser : FastUser, new()
    {
        var indexKeysDefinition = Builders<TUser>.IndexKeys.Ascending(user => user.NormalizedEmail);
        return usersCollection.Indexes.CreateOneAsync(
            new CreateIndexModel<TUser>(indexKeysDefinition),
            null,
            cancellationToken);
    }

    public static Task CreateFastUserIndexes(this IMongoCollection<FastUser> usersCollection, CancellationToken cancellationToken = default)
    {
        return CreateFastUserIndexes<FastUser>(usersCollection, cancellationToken);
    }

    public static MongoFastAuthBuilder AddFastAuthWithMongo<TUser>(this IServiceCollection services, Action<MongoFastAuthOptions> optionAction)
        where TUser : FastUser, new()
    {
        MongoFastAuthOptions authOptions = new();
        optionAction(authOptions);
        services.AddSingleton(authOptions);
        services.AddSingleton<FastAuthOptions>(authOptions);

        services.AddScoped<
            IFastUserStore<TUser, FastRefreshToken<TUser>, string>,
            FastUserStore<TUser, FastRefreshToken<TUser>>>();
        
        services.AddScoped<
            IFastAuthService<TUser>,
            FastAuthService<TUser>>();

        services.AddScoped<IFastAuthService<TUser, FastRefreshToken<TUser>, string>>(
            sp => sp.GetService<IFastAuthService<TUser>>()!);

        return new()
        {
            AuthOptions = authOptions,
            Services = services,
            UserType = typeof(TUser),
            RefreshTokenType = typeof(FastRefreshToken<TUser>)
        };
    }

    public static MongoFastAuthBuilder AddFastAuthWithMongo(this IServiceCollection services, Action<MongoFastAuthOptions> optionAction)
    {
        MongoFastAuthOptions authOptions = new();
        optionAction(authOptions);
        services.AddSingleton(authOptions);
        services.AddSingleton<FastAuthOptions>(authOptions);

        services.AddScoped<
            IFastUserStore<FastUser, FastRefreshToken, string>,
            FastUserStore<FastUser, FastRefreshToken>>();

        services.AddScoped<IFastAuthService, FastAuthService>();

        services.AddScoped<IFastAuthService<FastUser, FastRefreshToken, string>>(sp => sp.GetService<IFastAuthService>()!);

        return new()
        {
            AuthOptions = authOptions,
            Services = services,
            UserType = typeof(FastUser),
            RefreshTokenType = typeof(FastRefreshToken)
        };
    }

    public static MongoFastAuthBuilder AddMongoStartupHostedService(this MongoFastAuthBuilder builder)
    {
        Type implmentationType = typeof(MongoStartupService<,>)
                            .MakeGenericType(builder.UserType!, builder.RefreshTokenType!);
        builder.Services!
            .TryAddEnumerable(ServiceDescriptor.Singleton(typeof(IHostedService), implmentationType));

        return builder;
    }

    public static TUser MapClaimsToFastUser<TUser>(this ClaimsPrincipal claimsPrincipal)
        where TUser : FastUser, new()
    {
        TUser fastUser = new();
        foreach (var claim in claimsPrincipal.Claims)
        {
            if (claim.Type == JwtRegisteredClaimNames.Email)
            {
                fastUser.Email = claim.Value;
                continue;
            }
            if (claim.Type == JwtRegisteredClaimNames.Sub)
            {
                fastUser.Id = claim.Value;
                continue;
            }
            if (claim.Type == nameof(FastUser.CreatedAt))
            {
                fastUser.CreatedAt = DateTime.Parse(claim.Value);
                continue;
            }
        }
        return fastUser;
    }

    public static FastUser MapClaimsToFastUser(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.MapClaimsToFastUser<FastUser>();
    }
}
