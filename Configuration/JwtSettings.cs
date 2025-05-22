namespace stocktaking_auth.Configuration;

public class JwtSettings
{
    public const string SectionName = "Jwt";

    public string Key { get; set; } = null!;
    public string Issuer { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public int AccessTokenExpirationMinutes { get; set; } = 5;
    public int RefreshTokenExpirationDays { get; set; } = 30;
}
