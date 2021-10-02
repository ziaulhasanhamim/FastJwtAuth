using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.Core.Entities
{
    public interface IFastRefreshToken<TUserKey>
    {
        public string? Id { get; set; }

        public TUserKey? UserId { get; set; }

        /// <summary>
        /// ExpireDate for RefreshToken. Generally Stored in utc
        /// </summary>
        public DateTime ExpiresAt { get; set; }
    }
}
