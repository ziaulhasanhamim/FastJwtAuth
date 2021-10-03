using FastJwtAuth.Core.Entities;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.EFCore.Entities
{
    public class FastRefreshToken<TUserKey, TUser> : IFastRefreshToken<TUserKey>
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

    public class FastRefreshToken<TUser> : FastRefreshToken<Guid, TUser>
        where TUser : FastUser
    {

    }

    public class FastRefreshToken : FastRefreshToken<FastUser>
    {

    }
}
