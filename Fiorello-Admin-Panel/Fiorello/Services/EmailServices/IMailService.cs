using Fiorello.Data;

namespace Fiorello.Services.EmailServices
{
    public interface IMailService
    {
        Task SendEmailAsync(RequestEmail requestEmail);
    }
}
