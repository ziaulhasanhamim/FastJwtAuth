using FastJwtAuth.Core.Services;
using FastJwtAuth.EFCore.Entities;
using FastJwtAuth.EFCore.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth
{
    public static class Extensions
    {
        public static void ConfigureAuthModels<TUser, TKey>(this ModelBuilder builder, FastAuthOptions authOptions)
            where TUser : FastUser<TKey>
        {
            builder.Entity<TUser>();
            if (authOptions.UseRefreshToken)
            {
                builder.Entity<FastRefreshToken<TKey, TUser>>();
            }
        }

        public static void ConfigureAuthModels(this ModelBuilder builder, FastAuthOptions authOptions)
        {
            builder.Entity<FastUser>();
            if (authOptions.UseRefreshToken)
            {
                builder.Entity<FastRefreshToken>();
            }
        }

        public static void AddFastAuthWithEFCore<TUser, TKey, TDbContext>(this IServiceCollection services, Action<FastAuthOptions> optionAction)
            where TUser : FastUser<TKey>, new()
            where TDbContext : DbContext
        {
            FastAuthOptions authOptions = new();
            optionAction(authOptions);
            services.AddSingleton(authOptions);
            services.AddScoped<
                IFastUserStore<TUser, FastRefreshToken<TKey, TUser>>,
                FastUserStore<TUser, FastRefreshToken<TKey, TUser>, TKey, TDbContext>>();
            services.AddScoped<
                IFastAuthService<TUser, FastRefreshToken<TKey, TUser>>,
                FastAuthService<TUser, FastRefreshToken<TKey, TUser>>>();
        }

        public static void AddFastAuthWithEFCore<TDbContext>(this IServiceCollection services, Action<FastAuthOptions> optionAction)
            where TDbContext : DbContext
        {
            FastAuthOptions authOptions = new();
            optionAction(authOptions);
            services.AddSingleton(authOptions);
            services.AddScoped<
                IFastUserStore<FastUser, FastRefreshToken>,
                FastUserStore<FastUser, FastRefreshToken, Guid, TDbContext>>();
            services.AddScoped<IFastAuthService, FastAuthService>();
            services.AddScoped<IFastAuthService<FastUser, FastRefreshToken>>(sp => sp.GetService<IFastAuthService>()!); ;
        }
    }
}
