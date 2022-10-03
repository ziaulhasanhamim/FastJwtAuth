namespace FastJwtAuth.MongoDB;

using global::MongoDB.Bson.Serialization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

public static class Extensions
{
    public static void AddFastAuthWithMongo<TUser, TRefreshToken>(
        this IServiceCollection services,
        Action<MongoFastAuthOptions<TUser, TRefreshToken>> optionAction)
        where TUser : FastUser, new()
        where TRefreshToken : FastRefreshToken<TUser>, new()
    {
        MongoFastAuthOptions<TUser, TRefreshToken> authOptions = new();
        optionAction(authOptions);
        if (authOptions is { DefaultTokenCreationOptions.SigningCredentials: null })
        {
            throw new ArgumentNullException("DefaultTokenCreationOptions.SigningCredentials", "You should set DefaultTokenCreationOptions.SigningCredentials first");
        }
        services.AddSingleton(authOptions);

        services.AddScoped<
            IFastAuthService<TUser>,
            FastAuthService<TUser>>();

        services.AddScoped<IFastAuthService<TUser, FastRefreshToken<TUser>>>(
            sp => sp.GetService<IFastAuthService<TUser>>()!);
    }

    public static void AddFastAuthWithMongo<TUser>(
        this IServiceCollection services,
        Action<MongoFastAuthOptions<TUser, FastRefreshToken<TUser>>> optionAction)
        where TUser : FastUser, new()
    {
        MongoFastAuthOptions<TUser> authOptions = new();
        optionAction(authOptions);
        if (authOptions is { DefaultTokenCreationOptions.SigningCredentials: null })
        {
            throw new ArgumentNullException(
                "DefaultTokenCreationOptions.SigningCredentials",
                "You should set DefaultTokenCreationOptions.SigningCredentials first");
        }
        services.AddSingleton(authOptions);
        services.AddSingleton<MongoFastAuthOptions<TUser, FastRefreshToken<TUser>>>(authOptions);

        services.AddScoped<
            IFastAuthService<TUser>,
            FastAuthService<TUser>>();

        services.AddScoped<IFastAuthService<TUser, FastRefreshToken<TUser>>>(
            sp => sp.GetService<IFastAuthService<TUser>>()!);
    }

    public static void AddFastAuthWithMongo(this IServiceCollection services, Action<MongoFastAuthOptions<FastUser, FastRefreshToken>> optionAction)
    {
        MongoFastAuthOptions authOptions = new();
        optionAction(authOptions);
        if (authOptions is { DefaultTokenCreationOptions.SigningCredentials: null })
        {
            throw new ArgumentNullException(
                "DefaultTokenCreationOptions.SigningCredentials",
                "You should set DefaultTokenCreationOptions.SigningCredentials first");
        }
        services.AddSingleton(authOptions);
        services.AddSingleton<MongoFastAuthOptions<FastUser, FastRefreshToken>>(authOptions);

        services.AddScoped<IFastAuthService, FastAuthService>();

        services.AddScoped<IFastAuthService<FastUser, FastRefreshToken>>(sp => sp.GetService<IFastAuthService>()!);
    }

    public static TUser ToFastUser<TUser>(this ClaimsIdentity claimsIdentity)
        where TUser : FastUser, new()
    {
        TUser fastUser = new();
        foreach (var claim in claimsIdentity.Claims)
        {
            if (claim.Type == JwtRegisteredClaimNames.Email)
            {
                fastUser.Email = claim.Value;
                continue;
            }
            if (claim.Type == JwtRegisteredClaimNames.UniqueName)
            {
                fastUser.Username = claim.Value;
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

    public static FastUser MapClaimsToFastUser(this ClaimsIdentity claimsIdentity) =>
        claimsIdentity.ToFastUser<FastUser>();
}
