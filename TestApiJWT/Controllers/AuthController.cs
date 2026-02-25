using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestApiJWT.Models;
using TestApiJWT.Services;

namespace TestApiJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthServices _authServices;

        public AuthController(IAuthServices authServices)
        {
            _authServices = authServices;
        }
        [HttpPost("Register")]
        public async Task<IActionResult> RegisterAsync([FromBody]RegisterModel model)
        {
            if(!ModelState.IsValid) 
            {
                return BadRequest(ModelState);
            }
            var result = await _authServices.RegisterAsync(model);
            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }
            return Ok(new 
            { 
             result.Token,
             result.Expireon
            });


            //return Ok(result);

        }

        [HttpPost("login")]
        public async Task<IActionResult> GetTokenAsync([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result=await _authServices.GetTokenAsync(model);
            if (!result.IsAuthenticated)
            {
                return BadRequest($"{result.Message}");

            }
            return Ok(result);
        }

        [HttpPost("addrole")]
        public async Task<IActionResult>AddRoleAsync(AddRoleModel model)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            
            var result=await _authServices.AddRoleAsync(model); 

            //if (result !=null)
            //{
            //    return BadRequest(result);
            //}

            //return Ok(model);
            if(!string.IsNullOrEmpty(result))
            {
                return BadRequest(result);
            }
            return Ok(model);
        }

    }
}
