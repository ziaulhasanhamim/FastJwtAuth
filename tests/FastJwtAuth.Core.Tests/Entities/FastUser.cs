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

        public string? NormalizedEmail { get; set; }

        public string? Email { get; set; }

        public string? PasswordHash { get; set; }

        public DateTime CreatedAt { get; set; }

        public DateTime? LastLogin { get; set; }

    }
}
