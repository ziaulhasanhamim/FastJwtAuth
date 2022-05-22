using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace GettingStarted.Dtos
{
    public record UserResponse(
        Guid Id,
        string Email,
        string Username,
        DateTime CreatedAt);
}
