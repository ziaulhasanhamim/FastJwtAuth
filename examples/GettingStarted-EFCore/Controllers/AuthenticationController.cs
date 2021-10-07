using FastJwtAuth;
using FastJwtAuth.EFCore.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using GettingStarted.Dtos;
using System.Diagnostics;

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
            var authResult = await _authService.CreateUserAsync(user, request.Password);
            if (authResult is SuccessAuthResult<FastUser> successResult)
            {
                AuthResponse authRes = new(successResult.AccessToken, successResult.RefreshToken);
                return Ok(authRes);
            }
            return BadRequest(authResult);
        }

        [HttpPost("login")]
        public async Task<IActionResult> LoginUser([FromBody] LoginUserRequest request)
        {
            var authResult = await _authService.LoginUserAsync(request.Email, request.Password);
            if (authResult is SuccessAuthResult<FastUser> successResult)
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
            if (authResult is SuccessAuthResult<FastUser> successResult)
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
