using JwtAuth.Entities;
using JwtAuth.Models;
using JwtAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        [HttpPost("Register")]
        public async Task<ActionResult<UserResponseDto>> RegisterAsync(UserDto request)
        {
            var user = await authService.Register(request);
            if(user == null)
            {
                return BadRequest("Username already exists");
            }
            UserResponseDto userResponseDto = new UserResponseDto
            {
                Username = user.Username,
                Role = user.Role,
            };
            return Ok(userResponseDto);
        }


        [HttpPost("Login")]
        public async Task<ActionResult<TokenResponseDto>> LoginAsync(UserDto Request)
        {
            var result = await authService.Login(Request);

            if (result == null)
                return BadRequest("Invalid credentials!");

            return Ok(result);       
        }


        [HttpPost("Refresh-Token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshTokenAsync(RefreshTokenRequestDto Request)
        {
            var result = await authService.RefreshTokenAsync(Request);
            if (result == null) return Unauthorized("Unauthorized!");
            return Ok(result);
        }




        [HttpGet("TryAuth")]
        [Authorize]
        public IActionResult method()
        {
            return Content("Here is you are authorized");
        }


        [HttpGet("AdminRole")]
        [Authorize(Roles = "Admin")]
        public IActionResult methodA()
        {
            return Content("I am an admin");
        }

    }
}
