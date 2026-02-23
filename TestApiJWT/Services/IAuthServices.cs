using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    public interface IAuthServices
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
    }
}
