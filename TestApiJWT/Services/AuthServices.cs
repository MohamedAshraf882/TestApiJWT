using Microsoft.AspNetCore.Identity;
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

         public AuthServices(UserManager<ApplicationUser> user, IOptions<JWT> jwt)
        {
            _user = user;
            _jwt = jwt.Value;
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
