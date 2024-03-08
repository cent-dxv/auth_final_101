

using Microsoft.AspNetCore.Identity;

namespace auth_final_101.Models;

public class Identity_User : IdentityUser
{
    public string? Name { get; set; }
  }
