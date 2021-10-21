using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.MongoDB
{
    public class MongoFastAuthOptions : FastAuthOptions
    {
        public string? MongoDbName { get; set; }

        public Func<IServiceProvider, IMongoDatabase>? MongoDatabaseGetter { get; set; }
    }
}
