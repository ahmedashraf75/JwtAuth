using Azure.Core;
using JwtAuth.Data;
using JwtAuth.Entities;
using JwtAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuth.Services
{
    public class AuthService(UserDbContext context, IConfiguration configuration) : IAuthService
    {
        public async Task<User> Register(UserDto request)
        {
            bool userExists = await context.Users.AnyAsync(user => user.Username == request.Username);
            if (userExists) return null;
            var newUser = new User
            {
                Username = request.Username,
                Role = "User"
            };
            var hasher = new PasswordHasher<User>();
            var passwordHasher = hasher.HashPassword(newUser, request.Password);
            newUser.Password = passwordHasher;
            context.Users.Add(newUser);
            await context.SaveChangesAsync();
            return newUser;
        }

        public async Task<TokenResponseDto> Login(UserDto request)
        {
            User? user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null) return null;
            var hasher = new PasswordHasher<User>();
            var verifyUserPassword = hasher.VerifyHashedPassword(user, user.Password, request.Password);
            if (PasswordVerificationResult.Failed == verifyUserPassword) return null;
            TokenResponseDto tokens = await CreateRefreshAndAccessToken(user);
            return tokens;
        }


        public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            if (string.IsNullOrEmpty(request.RefresherToken))
                return null;
            int Id = request.UserId;
            string refreshToken = request.RefresherToken;
            var result = await ValidateRefreshTokenAndUser(Id, refreshToken);
            return result;
        }

        private async Task<TokenResponseDto?> ValidateRefreshTokenAndUser(int Id, string refreshToken)
        {
            var user = await context.Users.FindAsync(Id);
            if (user == null ||
                user.RefreshToken != refreshToken ||
                user.TokenExpirationDate <= DateTime.UtcNow)
            {
                if (user != null)
                {
                    user.RefreshToken = null;
                    user.TokenExpirationDate = null;
                    await context.SaveChangesAsync();
                }
                return null;
            }
            return await CreateRefreshAndAccessToken(user);
        }
        private async Task<TokenResponseDto> CreateRefreshAndAccessToken(User user)
        {
            var AccessTokenExpiration  = DateTime.UtcNow.AddDays(1);
            var RefreshTokenExpiration = DateTime.UtcNow.AddDays(7);
            return new TokenResponseDto
            {
                Accesstoken = CreateToken(user,AccessTokenExpiration),
                RefreshToken = await GenerateAndSaveRefreshTokenAsync(user,RefreshTokenExpiration),
                AccessTokenExpiration = AccessTokenExpiration,
                RefreshTokenExpiration = RefreshTokenExpiration,
                
            };
        }
        private async Task<string> GenerateAndSaveRefreshTokenAsync(User user,DateTime RefreshTokenExpiration)
        {
            user.RefreshToken = GenerateRefreshToken();
            user.TokenExpirationDate = RefreshTokenExpiration;
            await context.SaveChangesAsync();
            return user.RefreshToken;
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
            }
            return Convert.ToBase64String(randomNumber);
        }
        private string CreateToken(User user , DateTime AccessTokenExpiration)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier , user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role),
            };
            var key = new SymmetricSecurityKey(
                 Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
            issuer: configuration.GetValue<string>("AppSettings:Issuer"),
            audience: configuration.GetValue<string>("AppSettings:Audience"),
            claims: claims,
            expires: AccessTokenExpiration,
            signingCredentials: creds
            );
            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(tokenDescriptor);
        }

       
    }
}
