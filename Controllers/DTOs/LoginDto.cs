using System.ComponentModel.DataAnnotations;
using stocktaking_auth.Models;

namespace stocktaking_auth.Dtos.Auth;

public class LoginDto
{
  [Required]
  [EmailAddress]
  public string Email { get; set; } = null!;

  [Required]
  [DataType(DataType.Password)]
  public string Password { get; set; } = null!;
}
