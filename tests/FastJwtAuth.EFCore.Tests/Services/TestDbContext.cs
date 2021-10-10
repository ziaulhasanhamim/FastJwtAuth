using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;

namespace FastJwtAuth.EFCore.Tests.Services
{
    public class TestDbContext : DbContext
    {
        private TestDbContext()
        {

        }

        public static TestDbContext Init()
        {
            TestDbContext dbContext = new();
            dbContext.Database.EnsureCreated();
            return dbContext;
        }

        public static async Task<TestDbContext> InitAsync()
        {
            TestDbContext dbContext = new();
            await dbContext.Database.EnsureCreatedAsync();
            return dbContext;
        }

        public DbSet<FastUser> Users { get; set; } = null!;

        public DbSet<FastRefreshToken> RefreshTokens { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseInMemoryDatabase(Guid.NewGuid().ToString());
            base.OnConfiguring(optionsBuilder);
        }

        public override async ValueTask DisposeAsync()
        {
            await Database.EnsureDeletedAsync();
            await base.DisposeAsync();
        }

        public override void Dispose()
        {
            Database.EnsureDeleted();
            base.Dispose();
        }
    }
}
