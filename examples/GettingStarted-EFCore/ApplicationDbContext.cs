using FastJwtAuth;
using FastJwtAuth.EFCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace GettingStarted
{
    public class ApplicationDbContext : DbContext
    {
        private readonly EFCoreFastAuthOptions _authOptions;
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, EFCoreFastAuthOptions authOptions)
            : base(options)
        {
            _authOptions = authOptions;
        }

        public DbSet<FastUser> Users { get; set; } // optional

        public DbSet<FastRefreshToken> RefreshTokens { get; set; } // optional

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.ConfigureAuthModels(_authOptions);
            base.OnModelCreating(modelBuilder);
        }
    }
}
