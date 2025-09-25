using System.ComponentModel.DataAnnotations;

namespace ElegantEssence.ViewModels
{
    public class VerfyEmailViewModel
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress]
        public string Email { get; set; }
    }
}
