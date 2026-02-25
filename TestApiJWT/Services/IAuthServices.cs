using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    public interface IAuthServices
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> GetTokenAsync(LoginModel model);

        Task<string> AddRoleAsync(AddRoleModel model);
    }
}
