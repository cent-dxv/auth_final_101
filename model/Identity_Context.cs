

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;




namespace auth_final_101.Models;

public class Identity_Context : IdentityDbContext<Identity_User>
{
    public Identity_Context(DbContextOptions<Identity_Context> options) : base(options) { }

}
