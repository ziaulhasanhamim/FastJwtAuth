using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace GettingStarted.Dtos
{
    public record AuthResponse(
        string AccessToken,
        string RefreshToken);
}
