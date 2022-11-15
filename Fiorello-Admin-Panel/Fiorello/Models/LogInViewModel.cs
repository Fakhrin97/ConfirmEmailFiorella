using System.ComponentModel.DataAnnotations;

namespace Fiorello.Models
{
    public class LogInViewModel
    {
        public string Username { get; set; }

        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
