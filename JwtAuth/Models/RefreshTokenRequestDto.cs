using System.ComponentModel.DataAnnotations;

namespace JwtAuth.Models
{
    public class RefreshTokenRequestDto
    {
        [Required]
        public int UserId { get; set; }
        [Required]
        public string? RefresherToken { get; set; }
    }
}
