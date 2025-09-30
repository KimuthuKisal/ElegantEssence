using System.ComponentModel.DataAnnotations;

namespace ElegantEssence.ViewModels
{
    public class ChangePasswordViewModel
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Token { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [StringLength(32, MinimumLength = 8, ErrorMessage = "The password must have minimun 8 characters and maximum 32 characters.")]
        [Display(Name = "New Password")]
        [Compare("NewConfirmPassword", ErrorMessage = "Password does not match")]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "Confirm Password is required.")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        public string NewConfirmPassword { get; set; }
    }
}
