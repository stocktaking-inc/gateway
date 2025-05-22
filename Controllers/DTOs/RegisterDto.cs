using System.ComponentModel.DataAnnotations;
using stocktaking_auth.Models;

namespace stocktaking_auth.Dtos.Auth;

public class RegisterDto
{
  [Required]
  [StringLength(100, MinimumLength = 2)]
  public string Name { get; set; } = null!;

  [Required]
  [EmailAddress]
  public string Email { get; set; } = null!;

  [Required]
  [StringLength(100, MinimumLength = 6)]
  [DataType(DataType.Password)]
  public string Password { get; set; } = null!;
}
