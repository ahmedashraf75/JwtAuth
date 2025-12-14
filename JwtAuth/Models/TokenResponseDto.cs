namespace JwtAuth.Models
{
    public class TokenResponseDto
    {
        public required string Accesstoken { get; set; }
        public required string RefreshToken { get; set; }
        public DateTime AccessTokenExpiration { get; set; } 
        public DateTime RefreshTokenExpiration { get; set; } 
    }

}

