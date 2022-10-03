using FastJwtAuth.Core.Entities;
using System;

namespace FastJwtAuth.Core.Tests.Entities
{
    public sealed class FastRefreshToken : IFastRefreshToken<Guid>
    {
        public string? Id { get; set; }

        public Guid UserId { get; set; }

        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set ; }
    }
}
