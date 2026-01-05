using Microsoft.AspNetCore.Identity;

namespace ElegantEssence.Models
{
    public class Users : IdentityUser
    {
        public string FullName { get; set; }
    }
}
