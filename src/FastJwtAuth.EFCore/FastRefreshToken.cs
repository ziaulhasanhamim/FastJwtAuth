using FastJwtAuth.Core.Entities;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.EFCore
{
    public class FastRefreshToken<TUser, TUserKey> : IFastRefreshToken<TUserKey>
        where TUser : FastUser<TUserKey>
    {
        [Key]
        public string? Id { get; set; }

        [Required]
        public TUserKey? UserId { get; set; }

        [Required, ForeignKey(nameof(UserId))]
        public TUser? User { get; set; }

        [Required]
        public DateTime ExpiresAt { get; set; }
    }

    public class FastRefreshToken<TUser> : FastRefreshToken<TUser, Guid>
        where TUser : FastUser<Guid>, new()
    {

    }

    public class FastRefreshToken : FastRefreshToken<FastUser>
    {

    }
}
