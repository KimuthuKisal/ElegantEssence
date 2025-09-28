using ElegantEssence.Models;
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

        public AccountController(SignInManager<Users> signInManager, UserManager<Users> userManager, RoleManager<IdentityRole> roleManager)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.roleManager = roleManager;
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

            var user = await userManager.FindByNameAsync(verifyEmailModel.Email);

            if (user == null)
            {
                return View(verifyEmailModel);
            }
            else
            {
                return RedirectToAction("ChangePassword", "Account", new { username = user.UserName });
            }
        }

        [HttpGet]
        public IActionResult ChangePassword(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                return RedirectToAction("VerifyEmail", "Account");
            }

            return View(new ChangePasswordViewModel { Email = username });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel newPasswordmodel)
        {
            if (!ModelState.IsValid)
            {
                return View(newPasswordmodel);
            }

            var user = await userManager.FindByNameAsync(newPasswordmodel.Email);

            if (user == null)
            {
                return View(newPasswordmodel);
            }

            var result = await userManager.RemovePasswordAsync(user);

            if (result.Succeeded) 
            {
                return RedirectToAction("Login", "Account", new { username = user.UserName });
            }
            else
            {
                return View(newPasswordmodel);
            }

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
