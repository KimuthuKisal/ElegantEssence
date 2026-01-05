using ElegantEssence.Models;
using ElegantEssence.Services;
using ElegantEssence.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ElegantEssence.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<Users> signInManager;
        private readonly UserManager<Users> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IEmailService _emailService;

        public AccountController(SignInManager<Users> signInManager, UserManager<Users> userManager, RoleManager<IdentityRole> roleManager, IEmailService emailService)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.roleManager = roleManager;
            this._emailService = emailService;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel loginModel)
        {
            if(!ModelState.IsValid)
            {
                return View(loginModel);
            }

            var result = await signInManager.PasswordSignInAsync(loginModel.Email, loginModel.Password, loginModel.RememberMe, false);

            if(result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }

            ModelState.AddModelError(string.Empty, "Login attempt is invalid.");
            return View(loginModel);
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel registerModel)
        {
            if (!ModelState.IsValid)
            {
                return View(registerModel);
            }

            var user = new Users
            {
                FullName = registerModel.Name,
                UserName = registerModel.Email,
                Email = registerModel.Email,
                NormalizedEmail = registerModel.Email.ToUpper(),
                NormalizedUserName = registerModel.Email.ToUpper()
            };

            var result = await userManager.CreateAsync(user, registerModel.Password);

            if (result.Succeeded)
            {
                var roleExist = await roleManager.RoleExistsAsync("User");

                if(!roleExist)
                {
                    var role = new IdentityRole("User");
                    await roleManager.CreateAsync(role);
                }

                await userManager.AddToRoleAsync(user, "User");

                await signInManager.SignInAsync(user, isPersistent: false);

                return RedirectToAction("Login", "Account");
            }

            ModelState.AddModelError(string.Empty, "Register attempt is invalid.");
            return View(registerModel);
        }

        [HttpGet]
        public IActionResult VerifyEmail()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyEmail(VerifyEmailViewModel verifyEmailModel)
        {
            if (!ModelState.IsValid)
            {
                return View(verifyEmailModel);
            }

            var user = await userManager.FindByEmailAsync(verifyEmailModel.Email);

            //var user = await userManager.FindByNameAsync(verifyEmailModel.Email);

            if (user == null)
            {
                return View(verifyEmailModel);
            }
            //else
            //{
            //    return RedirectToAction("ChangePassword", "Account", new { username = user.UserName });
            //}

            var resetToken = await userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action("ChangePassword", "Account", new { email = verifyEmailModel.Email, token = resetToken}, Request.Scheme);

            var subject = "Password Reset";
            var body = $"Click here to reset your password. <a href = '{resetLink}'>Reset Password</a>";

            await _emailService.SendEmailAsync(verifyEmailModel.Email, subject, body);

            return RedirectToAction("EmailSent", "Account");
        }

        //[HttpGet]
        //public IActionResult ChangePassword(string username)
        //{
        //    if (string.IsNullOrEmpty(username))
        //    {
        //        return RedirectToAction("VerifyEmail", "Account");
        //    }

        //    return View(new ChangePasswordViewModel { Email = username });
        //}

        [HttpGet]
        public IActionResult ChangePassword(string email, string token)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
            {
                return RedirectToAction("VerifyEmail", "Account");
            }

            var model = new ChangePasswordViewModel
            {
                Email = email,
                Token = token
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel newPasswordmodel)
        {
            if (!ModelState.IsValid)
            {
                return View(newPasswordmodel);
            }

            //var user = await userManager.FindByNameAsync(newPasswordmodel.Email);
            var user = await userManager.FindByEmailAsync(newPasswordmodel.Email);

            if (user == null)
            {
                return View(newPasswordmodel);
            }

            //var result = await userManager.RemovePasswordAsync(user);
            var result = await userManager.ResetPasswordAsync(user, newPasswordmodel.Token, newPasswordmodel.NewPassword);

            if (result.Succeeded) 
            {
                //return RedirectToAction("Login", "Account", new { username = user.UserName });
                return RedirectToAction("Login", "Account");
            }
            else
            {
                return View(newPasswordmodel);
            }

        }

        [HttpGet]
        public IActionResult EmailSent()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
