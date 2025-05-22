using stocktaking_auth.Models;
namespace stocktaking_auth.Dtos.Auth;

public class UserProfileDto
{
  public UserProfileDto() { }

  public UserProfileDto(Profile profile)
  {
    Id = profile.Id;
    Name = profile.Name;
    Email = profile.Email;
  }

  public int Id { get; set; }
  public string Name { get; set; } = null!;
  public string Email { get; set; } = null!;
}
