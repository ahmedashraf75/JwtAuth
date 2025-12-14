namespace JwtAuth.Entities
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty; 
        public string Role {  get; set; } = string.Empty;
        public string? RefreshToken {  get; set; } 
        public DateTime? TokenExpirationDate { get; set; } 
    }
}
