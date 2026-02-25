using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.DotNet.Scaffolding.Shared.Messaging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestApiJWT.Helper;
using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    public class AuthServices : IAuthServices
    {
        private readonly UserManager<ApplicationUser> _user;
        private readonly JWT _jwt;
        private readonly RoleManager<IdentityRole>_roleManager;

         public AuthServices(UserManager<ApplicationUser> user, IOptions<JWT> jwt, RoleManager<IdentityRole> roleManager)
        {
            _user = user;
            _jwt = jwt.Value;
            _roleManager = roleManager;
        }

        public async Task<AuthModel> GetTokenAsync(LoginModel model)
        {
            var authmodel = new AuthModel();
            var user=await _user.FindByEmailAsync(model.Email);
            if (user == null|| !await _user.CheckPasswordAsync(user, model.Password)) 
            {
                

                authmodel.Message = "Email or password is incorrect!";
                return authmodel;
            }

            var jwtsecuritytoken = await CreateJwtTokenAsync(user);
            authmodel.Token = new JwtSecurityTokenHandler().WriteToken(jwtsecuritytoken);
            authmodel.IsAuthenticated = true;
            authmodel.Email = user.Email;
            authmodel.UserName = user.UserName;
            authmodel.Expireon = jwtsecuritytoken.ValidTo;
            var roleslist = await _user.GetRolesAsync(user);
            authmodel.Roles = roleslist.ToList();

            return authmodel;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _user.FindByEmailAsync(model.Email) != null)
            {
                return new AuthModel
                {
                    Message = "Email is already Register!"
                };
            }
                if (await _user.FindByNameAsync(model.UserName) != null)
                {
                    return new AuthModel
                    {
                        Message = "UserName is already Register!"
                    };
                }

            var user = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName= model.FirstName,
                LastName= model.LastName,
            };

           var result=await _user.CreateAsync(user,model.Password);
            if (!result.Succeeded)
            {
                var Errors=string.Empty;
                foreach (var error in result.Errors)
                {
                    Errors += $"{error.Description},";
                }
                return new AuthModel { Message= Errors };
            }

            await _user.AddToRoleAsync(user, "User");
            var jwtsecuritytoken = await CreateJwtTokenAsync(user);
            return new AuthModel
            {
                Email = user.Email,
                Expireon = jwtsecuritytoken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtsecuritytoken),
                UserName = user.UserName,
            };


        }

        public async Task<string> AddRoleAsync(AddRoleModel model) 
        { 
         var user=await _user.FindByIdAsync(model.UserId);
            if (user == null)
                return ("User not found!");

             if(!await _roleManager.RoleExistsAsync(model.Role))
                   return ("Role not found!");

            if(await _user.IsInRoleAsync(user,model.Role))
                return ("User already assigned to this role!");
            var result=await _user.AddToRoleAsync(user, model.Role);
            //if (result.Succeeded)
            //    return string.Empty;

            //return ("Failed to add role!");
            return result.Succeeded ? string.Empty : "Failed to add role!";



        }
        private async Task <JwtSecurityToken>CreateJwtTokenAsync(ApplicationUser user)
        {
            var userclaims=await _user.GetClaimsAsync(user);
            var roles=await _user.GetRolesAsync(user);
            var roleclaims = new List<Claim>();
            
            foreach(var role in roles)
            {
                roleclaims.Add(new Claim("roles", role));
            }
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim("uid",user.Id)
            }
            .Union(userclaims)
            .Union(roleclaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var Token = new JwtSecurityToken
                (
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);



                return Token;
        }

    }
}
