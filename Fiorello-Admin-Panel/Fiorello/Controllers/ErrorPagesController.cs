using Microsoft.AspNetCore.Mvc;

namespace Fiorello.Controllers
{
    public class ErrorPagesController : Controller
    {
        public IActionResult Error(int? code)
        {
            switch (code)
            {
                case 404:
                    return RedirectToAction(nameof(Error404));
                    
                case 500:
                    return RedirectToAction(nameof(Error500));

                default:
                    return RedirectToAction(nameof(Error404));                    
            }
            
        }
        public IActionResult Error404()
        {
            return View();
        }
        public IActionResult Error500()
        {
            return View();
        }
    }
}
