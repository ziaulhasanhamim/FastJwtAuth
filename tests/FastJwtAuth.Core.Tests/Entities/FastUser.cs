using FastJwtAuth.Core.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.Core.Tests.Entities
{
    public class FastUser : IFastUser<Guid>
    {
        public Guid Id { get; set; }

        public string? Email { get; set; }

        public string? PasswordHash { get; set; }

        public DateTime CreatedAt { get; set; }

        public DateTime? LastLogin { get; set; }
    }

    public class RefreshToken : IRefreshToken<Guid>
    {
        public string? Id { get; set; }

        public Guid UserId { get; set; }

        /// <summary>
        /// ExpireDate for RefreshToken. Generally Stored in utc
        /// </summary>
        public DateTime ExpiresAt { get; set; }
    }
}
