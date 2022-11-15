using Microsoft.AspNetCore.Identity;

namespace Fiorello.Data
{
    public class LocalizedIdentityErrorDescriper : IdentityErrorDescriber
    {
        public override IdentityError PasswordMismatch()
        {
            return new IdentityError
            {
                Code = nameof(PasswordMismatch),
                Description = "Shifre Duzgub Deyil"                
            };
        }
    }
}
