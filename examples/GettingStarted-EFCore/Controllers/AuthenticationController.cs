using FastJwtAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using GettingStarted.Dtos;
using System.Diagnostics;
using FastJwtAuth.EFCore;

namespace GettingStarted.Controllers
{
    [Route("/api/[controller]/")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IFastAuthService _authService;

        public AuthenticationController(IFastAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("create-user")]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
        {
            FastUser user = new()
            {
                Email = request.Email
            };
            var createResult = await _authService.CreateUserAsync(user, request.Password);
            if (!createResult.Success)
            {
                return BadRequest(createResult);
            }
            var authResult = await _authService.AuthenticateAsync(user);
            AuthResponse authRes = new(authResult.AccessToken, authResult.RefreshToken);
            return Ok(authRes);
        }

        [HttpPost("login")]
        public async Task<IActionResult> LoginUser([FromBody] LoginUserRequest request)
        {
            var authResult = await _authService.AuthenticateAsync(request.Email, request.Password);
            if (authResult is AuthResult<FastUser>.Success successResult)
            {
                AuthResponse authRes = new(successResult.AccessToken, successResult.RefreshToken);
                return Ok(authRes);
            }
            return BadRequest(authResult);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] string refreshToken)
        {
            var authResult = await _authService.RefreshAsync(refreshToken);
            if (authResult is AuthResult<FastUser>.Success successResult)
            {
                AuthResponse authRes = new(successResult.AccessToken, successResult.RefreshToken);
                return Ok(authRes);
            }
            return BadRequest(authResult);
        }

        [HttpGet("authorize")]
        [Authorize]
        public IActionResult Authorize()
        {
            var user = User.MapClaimsToFastUser();
            UserResponse res = new(
                user.Id,
                user.Email,
                user.CreatedAt);
            return Ok(res);
        }
    }
}
