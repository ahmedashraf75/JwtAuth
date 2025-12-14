using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuth.Services
{
    public interface IAuthService
    {
        Task<User?> Register(UserDto request);
        Task<TokenResponseDto?> Login(UserDto request);
        Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request);
    }
}
