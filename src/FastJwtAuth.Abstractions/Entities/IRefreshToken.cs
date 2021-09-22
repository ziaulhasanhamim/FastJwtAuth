using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.Abstractions.Entities
{
    public interface IRefreshToken<TUserId>
    {
        public string? Id { get; set; }

        public TUserId UserId { get; set; }

        /// <summary>
        /// ExpireDate for RefreshToken. Generally Stored in utc
        /// </summary>
        public DateTime ExpireDate { get; set; }
    }
}
