using System.ComponentModel.DataAnnotations;

namespace GettingStarted.Dtos
{
    public record LoginUserRequest(
        [EmailAddress, Required] string Email,
        [MinLength(8), Required] string Password);
}
