using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace Fiorello.Models.IdentityModels
{
    public class User : IdentityUser
    {
        public string Fullname { get; set; }
    }
}
