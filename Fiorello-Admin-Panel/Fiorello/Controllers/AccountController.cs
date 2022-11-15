using Fiorello.Data;
using Fiorello.Models;
using Fiorello.Models.IdentityModels;
using Fiorello.Services.EmailServices;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NuGet.Protocol.Plugins;

namespace Fiorello.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IMailService _mailManager;

        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager, RoleManager<IdentityRole> roleManager, IMailService mailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _mailManager = mailService;
        }

        public IActionResult Index()
        {
            return RedirectToAction(nameof(LogIn));
        }

        public IActionResult Register()
        {
            return View();
        }

        public IActionResult LogIn()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogIn(LogInViewModel model)
        {
            if (ModelState.IsValid)
            {
                var existUser = await _userManager.FindByNameAsync(model.Username);

                if (existUser == null)
                {
                    ModelState.AddModelError("", "This User Not Exist");
                    return View();
                }

                var result = await _signInManager.PasswordSignInAsync(existUser, model.Password, false, true);

                if (result.IsNotAllowed)
                {
                    ModelState.AddModelError("", "Email tesdiqlenmelidir , zehmet olmasa Emailiniz yoxlayin");
                    return View();
                }

                if (result.IsLockedOut)
                {
                    ModelState.AddModelError("", "This Account Locked Out");
                    return View();
                }

                if (!result.Succeeded)
                {
                    ModelState.AddModelError("", "Password or Username Incorrect");
                    return View();
                }

                return RedirectToAction("Index", "Home");
            }

            return View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View();

            var existUser = await _userManager.FindByNameAsync(model.Username);

            if (existUser != null)
            {
                ModelState.AddModelError("", "Username Artiq Istifade Olunub");
                return View();
            }

            var user = new User
            {
                Fullname = model.Username,
                UserName = model.Username,
                Email = model.Email,
            };

            //var role = await _roleManager.CreateAsync(new IdentityRole { Name = "Admin" });

            var result = await _userManager.CreateAsync(user, model.Password);

            //await _userManager.AddToRoleAsync(user , "Admin");

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);

                }
                return View();
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var resetLink = Url.Action(nameof(ConfirmEmail), "Account", new { mail = model.Email, token }, Request.Scheme, Request.Host.ToString());

            var requestEmail = new RequestEmail
            {
                ToEmail = model.Email,
                Body = resetLink,
                Subject = "Confirm Email",
            };

            await _mailManager.SendEmailAsync(requestEmail);

            return RedirectToAction(nameof(LogIn));
        }
        
        public async Task<IActionResult> ConfirmEmail(string mail , string token )
        {
            var user = await _userManager.FindByEmailAsync(mail);   

            await _userManager.ConfirmEmailAsync(user, token);
            await _signInManager.SignInAsync(user, false);

            return RedirectToAction(nameof(Index));
        }      
        
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction(nameof(LogIn));
        }

        public IActionResult ChangePassword()
        {
            if (!User.Identity.IsAuthenticated)
                return RedirectToAction(nameof(LogIn));

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View();

            var existUser = await _userManager.FindByNameAsync(User.Identity.Name);

            if (existUser == null)
                return BadRequest();

            var result = await _userManager.ChangePasswordAsync(existUser, model.CurrentPassword, model.NewPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

                return View();
            }

            await _signInManager.SignOutAsync();

            return RedirectToAction(nameof(LogIn));
        }

        public IActionResult ForgetPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgetPassword(ForgetViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Bosh Gonedrile Bilemez");
                return View();
            }

            var existUser = await _userManager.FindByEmailAsync(model.Mail);

            if (existUser == null)
            {
                ModelState.AddModelError("", "Mail Duzgun DEyil");
                return View();
            }
           
            var token = await _userManager.GeneratePasswordResetTokenAsync(existUser);

            var resetLink = Url.Action(nameof(ResetPassword), "Account", new { mail = model.Mail, token }, Request.Scheme, Request.Host.ToString());

            var requestEmail = new RequestEmail
            {
                ToEmail = model.Mail,
                Body = resetLink,
                Subject = "Reset Link",
            };

            await _mailManager.SendEmailAsync(requestEmail);

            return RedirectToAction(nameof(LogIn));
        }

        public IActionResult ResetPassword(string mail, string token)
        {
            return View(new ResetPasswordViewModel
            {
                Mail = mail,
                Token = token,
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View();

            var user = await _userManager.FindByEmailAsync(model.Mail);

            if (user == null)
                return BadRequest();

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

            if(!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

                return View();
            }

            return RedirectToAction(nameof(LogIn));
        }
    }
}
