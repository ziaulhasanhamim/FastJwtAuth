using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.MongoDB
{
    public struct MongoFastAuthBuilder
    {
        public IServiceCollection? Services { get; set; }

        public MongoFastAuthOptions? AuthOptions { get; set; }

        public Type? UserType { get; set; }

        public Type? RefreshTokenType { get; set; }
    }
}
