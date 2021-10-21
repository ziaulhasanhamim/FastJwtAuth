using FastJwtAuth.Core.Entities;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.MongoDB
{
    public class FastRefreshToken<TUser> : IFastRefreshToken<string>
        where TUser : FastUser
    {
        [BsonId]
        public string? Id { get; set; }

        [BsonIgnore]
        public string? UserId 
        { 
            get => User?.Id; 
            set => throw new NotSupportedException("You can not set UserId field directly in mongo provider try changing User.Id field");
        }

        public TUser? User { get; set; }

        public DateTime ExpiresAt { get; set; }
    }

    public class FastRefreshToken : FastRefreshToken<FastUser>
    {

    }
}
