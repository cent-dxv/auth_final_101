using auth_final_101.Models;

// using Microsoft.AspNet.Identity.EntityFramework;

using Microsoft.AspNetCore.Mvc;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http.HttpResults;
using Org.BouncyCastle.Asn1.Iana;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Build.Framework;
using System.Text;

namespace auth_final_101.Controllers;
public record UserSession(string? Id, string? Name, string? Email, string? Role);




[Route("/")]
[ApiController]
public class AccountManagerController : ControllerBase
{


    private readonly UserManager<Identity_User> userManager;
    private readonly RoleManager<IdentityRole> roleManager;

    public AccountManagerController(UserManager<Identity_User> userManager, RoleManager<IdentityRole> roleManager)
    {
        this.userManager = userManager;
        this.roleManager = roleManager;
    }


    [HttpPost("regester")]

    public async Task<IActionResult> CreateAccount(UserRegester userDTO)
    {
        if (userDTO is null) return BadRequest("Model is empty");

        var newUser = new Identity_User()
        {
            Name = userDTO.Name,
            Email = userDTO.Email,
            PasswordHash = userDTO.Password,
            UserName = userDTO.Email
        };

        var user = await userManager.FindByEmailAsync(newUser.Email);


        if (user is not null) return BadRequest("User registered already");

        var createUser = await userManager.CreateAsync(newUser!, userDTO.Password);

        if (!createUser.Succeeded) return BadRequest("Error occured.. please try again" + createUser.Errors.FirstOrDefault()!.Description + "\n\n\n\n" + createUser.Errors);

        //Assign Default Role : Admin to first registrar; rest is user
        var checkAdmin = await roleManager.FindByNameAsync("Admin");
        if (checkAdmin is null)
        {
            await roleManager.CreateAsync(new IdentityRole() { Name = "Admin" });
            await userManager.AddToRoleAsync(newUser, "Admin");
            return Ok(" Admin Account Created");
        }
        else
        {
            var checkUser = await roleManager.FindByNameAsync("User");
            if (checkUser is null)
                await roleManager.CreateAsync(new IdentityRole() { Name = "User" });

            await userManager.AddToRoleAsync(newUser, "User");
            return Ok("Account Created");
        }
    }



    [HttpPost("login")]
    public async Task<IActionResult> LoginAccount(LoginUser loginDTO)
    {
        if (loginDTO == null)
            return BadRequest("Login container is empty");

        var getUser = await userManager.FindByEmailAsync(loginDTO.Email);

        if (getUser is null)
            return NotFound("User not found");

        bool checkUserPasswords = await userManager.CheckPasswordAsync(getUser, loginDTO.Password);

        if (!checkUserPasswords)
            return BadRequest("Invalid email/password");

        var getUserRole = await userManager.GetRolesAsync(getUser);

        var userSession = new UserSession(getUser.Id, getUser.Name, getUser.Email, getUserRole.First());

        string token = GenerateToken(userSession);
        return Ok(new { token = token!, status = "Login completed" });
    }


    private string GenerateToken(UserSession user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("YcxjOMewdFfeZFQm5iGAYxTjR23Z93rLbyZucty3"));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var userClaims = new[]
        {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            };
        // var config = Configuration.GetSection("Jwt");
       
        var token = new JwtSecurityToken(
            issuer: "https://localhost:5285",
            audience: "https://localhost:5285",
            claims: userClaims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}


