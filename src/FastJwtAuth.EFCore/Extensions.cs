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

namespace FastJwtAuth.EFCore
{
    public static class Extensions
    {
        private static void ConfigureAuthModels<TUser, TUserKey, TRefreshToken>(ModelBuilder builder, FastAuthOptions authOptions)
            where TUser : FastUser<TUserKey>, new()
            where TRefreshToken : FastRefreshToken<TUser, TUserKey>, new()
        {
            builder.Entity<TUser>();
            if (authOptions.UseRefreshToken)
            {
                builder.Entity<TRefreshToken>();
            }
        }

        public static void ConfigureAuthModels<TUser, TUserKey>(this ModelBuilder builder, FastAuthOptions authOptions)
            where TUser : FastUser<TUserKey>, new()
        {
            ConfigureAuthModels<TUser, TUserKey, FastRefreshToken<TUser, TUserKey>>(builder, authOptions);
        }

        public static void ConfigureAuthModels<TUser>(this ModelBuilder builder, FastAuthOptions authOptions)
            where TUser : FastUser, new()
        {
            ConfigureAuthModels<
                TUser, 
                Guid, 
                FastRefreshToken<TUser>>(builder, authOptions);
        }

        public static void ConfigureAuthModels(this ModelBuilder builder, FastAuthOptions authOptions)
        {
            ConfigureAuthModels<FastUser, Guid, FastRefreshToken>(builder, authOptions);
        }

        public static void AddFastAuthWithEFCore<TUser, TUserKey, TDbContext>(this IServiceCollection services, Action<FastAuthOptions> optionAction)
            where TUser : FastUser<TUserKey>, new()
            where TDbContext : DbContext
        {
            FastAuthOptions authOptions = new();
            optionAction(authOptions);
            services.AddSingleton(authOptions);

            services.AddScoped<
                IFastUserStore<TUser, FastRefreshToken<TUser, TUserKey>>,
                FastUserStore<TUser, TUserKey, FastRefreshToken<TUser, TUserKey>, TDbContext>>();

            services.AddScoped<
                IFastAuthService<TUser, FastRefreshToken<TUser, TUserKey>>,
                FastAuthService<TUser, FastRefreshToken<TUser, TUserKey>>>();
        }

        public static void AddFastAuthWithEFCore<TUser, TDbContext>(this IServiceCollection services, Action<FastAuthOptions> optionAction)
            where TUser : FastUser, new()
            where TDbContext : DbContext
        {
            FastAuthOptions authOptions = new();
            optionAction(authOptions);
            services.AddSingleton(authOptions);

            services.AddScoped<
                IFastUserStore<TUser, FastRefreshToken<TUser>>,
                FastUserStore<TUser, Guid, FastRefreshToken<TUser>, TDbContext>>();

            services.AddScoped<
                IFastAuthService<TUser>,
                FastAuthService<TUser>>();

            services.AddScoped<IFastAuthService<TUser, FastRefreshToken<TUser>>>(sp => sp.GetService<IFastAuthService<TUser>>()!);
        }

        public static void AddFastAuthWithEFCore<TDbContext>(this IServiceCollection services, Action<FastAuthOptions> optionAction)
            where TDbContext : DbContext
        {
            FastAuthOptions authOptions = new();
            optionAction(authOptions);
            services.AddSingleton(authOptions);

            services.AddScoped<
                IFastUserStore<FastUser, FastRefreshToken>,
                FastUserStore<FastUser, Guid, FastRefreshToken, TDbContext>>();

            services.AddScoped<IFastAuthService, FastAuthService>();

            services.AddScoped<IFastAuthService<FastUser, FastRefreshToken>>(sp => sp.GetService<IFastAuthService>()!);
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
}
