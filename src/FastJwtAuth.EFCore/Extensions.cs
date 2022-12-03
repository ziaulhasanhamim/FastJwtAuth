namespace FastJwtAuth.EFCore;

using FastJwtAuth.Core.Services;
using FastJwtAuth.EFCore.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Diagnostics;
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
        var userEntityBuilder = builder.Entity<TUser>();

        userEntityBuilder.HasKey(user => user.Id);
        userEntityBuilder.Property(user => user.PasswordHash)
            .IsRequired();
        userEntityBuilder.Property(user => user.CreatedAt)
            .IsRequired();

        ConfigureEmailBehavior(authOptions, userEntityBuilder);
        ConfigureUsernameBehavior(authOptions, userEntityBuilder);

        if (authOptions.UseRefreshToken)
        {
            builder.Entity<TRefreshToken>();
        }
    }

    private static void ConfigureEmailBehavior<TUser, TRefreshToken>(
        EFCoreFastAuthOptions<TUser, TRefreshToken> authOptions, EntityTypeBuilder<TUser> userEntityBuilder)
        where TUser : FastUser, new()
        where TRefreshToken : FastRefreshToken<TUser>, new()
    {
        if (authOptions.EmailState == FastFieldState.Nope)
        {
            userEntityBuilder.Ignore(user => user.Email);
            userEntityBuilder.Ignore(user => user.NormalizedEmail);
            return;
        }
        if (authOptions.EmailState == FastFieldState.Has)
        {
            userEntityBuilder.HasIndex(user => user.NormalizedUsername);
            return;
        }
        if (authOptions.EmailState == FastFieldState.Required)
        {
            userEntityBuilder.Property(user => user.Email)
                .IsRequired();
            userEntityBuilder.Property(user => user.NormalizedEmail)
                .IsRequired();
            userEntityBuilder.HasIndex(user => user.NormalizedEmail);
            return;
        }
#if NET6_0
    throw new NotImplementedException();
#elif NET7_0_OR_GREATER
    throw new UnreachableException();
#endif
    }

    private static void ConfigureUsernameBehavior<TUser, TRefreshToken>(
        EFCoreFastAuthOptions<TUser, TRefreshToken> authOptions, EntityTypeBuilder<TUser> userEntityBuilder)
        where TUser : FastUser, new()
        where TRefreshToken : FastRefreshToken<TUser>, new()
    {
        if (authOptions.UsernameState == FastFieldState.Nope)
        {
            userEntityBuilder.Ignore(user => user.Username);
            userEntityBuilder.Ignore(user => user.NormalizedUsername);
            return;
        }
        if (authOptions.UsernameState == FastFieldState.Has)
        {
            userEntityBuilder.HasIndex(user => user.NormalizedUsername);
            return;
        }
        if (authOptions.UsernameState == FastFieldState.Required)
        {
            userEntityBuilder.Property(user => user.Username)
                .IsRequired();
            userEntityBuilder.Property(user => user.NormalizedUsername)
                .IsRequired();
            userEntityBuilder.HasIndex(user => user.NormalizedUsername);
            return;
        }
#if NET6_0
    throw new NotImplementedException();
#elif NET7_0_OR_GREATER
    throw new UnreachableException();
#endif
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
        if (authOptions is
            {
                EmailState: FastFieldState.Nope,
                UsernameState: FastFieldState.Nope,
            })
        {
            throw new ArgumentException("User entity must have One of these EmailState or UsernameState");
        }
        if (authOptions is { DefaultTokenCreationOptions.SigningCredentials: null })
        {
            throw new ArgumentNullException(
                "DefaultTokenCreationOptions.SigningCredentials",
                "You should set DefaultTokenCreationOptions.SigningCredentials first");
        }
        services.AddSingleton(authOptions);

        services.AddScoped<
            IFastAuthService<TUser, TRefreshToken>,
            FastAuthService<TUser, TRefreshToken, TDbContext>>();
    }

    public static void AddFastAuthWithEFCore<TUser, TDbContext>(
        this IServiceCollection services,
        Action<EFCoreFastAuthOptions<TUser>> optionAction)
        where TUser : FastUser, new()
        where TDbContext : DbContext
    {
        EFCoreFastAuthOptions<TUser> authOptions = new();
        optionAction(authOptions);
        if (authOptions is
            {
                EmailState: FastFieldState.Nope,
                UsernameState: FastFieldState.Nope,
            })
        {
            throw new ArgumentException("User entity must have One of these EmailState or UsernameState");
        }
        if (authOptions is { DefaultTokenCreationOptions.SigningCredentials: null })
        {
            throw new ArgumentNullException(
                "DefaultTokenCreationOptions.SigningCredentials",
                "You should set DefaultTokenCreationOptions.SigningCredentials first");
        }
        services.AddSingleton(authOptions);
        services.AddSingleton<EFCoreFastAuthOptions<TUser, FastRefreshToken<TUser>>>(authOptions);

        services.AddScoped<
            IFastAuthService<TUser>,
            FastAuthService<TUser, TDbContext>>();

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
        if (authOptions is
            {
                EmailState: FastFieldState.Nope,
                UsernameState: FastFieldState.Nope,
            })
        {
            throw new ArgumentException("User entity must have One of these EmailState or UsernameState");
        }
        if (authOptions is { DefaultTokenCreationOptions.SigningCredentials: null })
        {
            throw new ArgumentNullException(
                "DefaultTokenCreationOptions.SigningCredentials",
                "You should set DefaultTokenCreationOptions.SigningCredentials first");
        }
        services.AddSingleton(authOptions);
        services.AddSingleton<EFCoreFastAuthOptions<FastUser, FastRefreshToken>>(authOptions);

        services.AddScoped<IFastAuthService, FastAuthService<TDbContext>>();

        services.AddScoped<IFastAuthService<FastUser, FastRefreshToken>>(
            sp => sp.GetService<IFastAuthService>()!);
    }
}
