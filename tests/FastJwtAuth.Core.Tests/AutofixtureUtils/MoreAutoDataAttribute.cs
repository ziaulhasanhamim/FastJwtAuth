using AutoFixture;
using AutoFixture.AutoNSubstitute;
using AutoFixture.Kernel;
using AutoFixture.Xunit2;
using FastJwtAuth.Core.Options;
using Microsoft.VisualStudio.TestPlatform.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace FastJwtAuth.Core.Tests.AutofixtureUtils
{
    public class MoreAutoDataAttribute : AutoDataAttribute
    {
        public MoreAutoDataAttribute()
            : base(() =>
            {
                Fixture fixture = new();
                fixture.Customize(new AutoNSubstituteCustomization());
                fixture.Customize<FastAuthOptions>(c => c.Without(options => options.SigningCredentials));
                return fixture;
            })
        {

        }
    }
}
