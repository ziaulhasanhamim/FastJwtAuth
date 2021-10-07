using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace GettingStarted.Dtos
{
    public record CreateUserRequest(
        [EmailAddress, Required] string Email,
        [MinLength(8), Required] string Password);
}
