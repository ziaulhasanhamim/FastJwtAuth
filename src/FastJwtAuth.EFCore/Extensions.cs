namespace FastJwtAuth.EFCore;

using FastJwtAuth.Core.Services;
using FastJwtAuth.EFCore.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

public static class Extensions
{
    public static void ConfigureAuthModels<TUser, TRefreshToken>(
        this ModelBuilder builder, 
        EFCoreFastAuthOptions<TUser, TRefreshToken> authOptions)
        where TUser : FastUser, new()
        where TRefreshToken : FastRefreshToken<TUser>, new()
    {
        builder.Entity<TUser>();
        if (authOptions.UseRefreshToken)
        {
            builder.Entity<TRefreshToken>();
        }
    }

    public static void ConfigureAuthModels<TUser>(
        this ModelBuilder builder, 
        EFCoreFastAuthOptions<TUser> authOptions)
        where TUser : FastUser, new()
    {
        ConfigureAuthModels<TUser, FastRefreshToken<TUser>>(builder, authOptions);
    }


    public static void ConfigureAuthModels(
        this ModelBuilder builder, 
        EFCoreFastAuthOptions authOptions)
    {
        ConfigureAuthModels<FastUser, FastRefreshToken>(builder, authOptions);
    }

    public static void AddFastAuthWithEFCore<TUser, TRefreshToken, TDbContext>(
        this IServiceCollection services, 
        Action<EFCoreFastAuthOptions<TUser, TRefreshToken>> optionAction)
        where TUser : FastUser, new()
        where TRefreshToken : FastRefreshToken<TUser>, new()
        where TDbContext : DbContext
    {
        EFCoreFastAuthOptions<TUser, TRefreshToken> authOptions = new();
        optionAction(authOptions);
        services.AddSingleton(authOptions);

        services.AddScoped<
            IFastUserStore<TUser, TRefreshToken>,
            FastUserStore<TUser, TRefreshToken, TDbContext>>();

        services.AddScoped<
            IFastAuthService<TUser, TRefreshToken>,
            FastAuthService<TUser, TRefreshToken>>();
    }

    public static void AddFastAuthWithEFCore<TUser, TDbContext>(
        this IServiceCollection services, 
        Action<EFCoreFastAuthOptions<TUser>> optionAction)
        where TUser : FastUser, new()
        where TDbContext : DbContext
    {
        EFCoreFastAuthOptions<TUser> authOptions = new();
        optionAction(authOptions);
        services.AddSingleton(authOptions);
        services.AddSingleton<EFCoreFastAuthOptions<TUser, FastRefreshToken<TUser>>>(authOptions);
        
        services.AddScoped<IFastUserStore<TUser>, FastUserStore<TUser, TDbContext>>();

        services.AddScoped<IFastUserStore<TUser, FastRefreshToken<TUser>>>(
            sp => sp.GetService<IFastUserStore<TUser>>()!);

        services.AddScoped<
            IFastAuthService<TUser>,
            FastAuthService<TUser>>();

        services.AddScoped<IFastAuthService<TUser, FastRefreshToken<TUser>>>(
            sp => sp.GetService<IFastAuthService<TUser>>()!);
    }

    public static void AddFastAuthWithEFCore<TDbContext>(
        this IServiceCollection services, 
        Action<EFCoreFastAuthOptions> optionAction)
        where TDbContext : DbContext
    {
        EFCoreFastAuthOptions authOptions = new();
        optionAction(authOptions);
        services.AddSingleton(authOptions);
        services.AddSingleton<EFCoreFastAuthOptions<FastUser, FastRefreshToken>>(authOptions);
        
        services.AddScoped<IFastUserStore, FastUserStore<TDbContext>>();

        services.AddScoped<IFastUserStore<FastUser, FastRefreshToken>>(
            sp => sp.GetService<IFastUserStore>()!);

        services.AddScoped<IFastAuthService, FastAuthService>();

        services.AddScoped<IFastAuthService<FastUser, FastRefreshToken>>(
            sp => sp.GetService<IFastAuthService>()!);
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
                fastUser.Id = Guid.Parse(claim.Value);
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
        return MapClaimsToFastUser<FastUser>(claimsPrincipal);
    }
}
