using System.ComponentModel.DataAnnotations.Schema;

namespace stocktaking_auth.Models;

[Table("profile")]
public class Profile
{
  [Column("id")]
  public int Id { get; set; }
  [Column("name")]
  public required string Name { get; set; } = string.Empty;
  [Column("email")]
  public required string Email { get; set; } = string.Empty;
  [Column("phone")]
  public string? Phone { get; set; }
  [Column("company")]
  public string? Company { get; set; }
  [Column("position")]
  public string? Position { get; set; }
  [Column("description")]
  public string? Description { get; set; }
  [Column("password_hash")]
  public required string PasswordHash { get; set; } = string.Empty;
  [Column("settings_id")]
  public int? SettingsId { get; set; }
  [Column("business_plan_id")]
  public int? BusinessPlanId { get; set; }
}
