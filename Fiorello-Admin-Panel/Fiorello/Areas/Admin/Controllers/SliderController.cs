using Fiorello.Areas.Admin.Models;
using Fiorello.DAL;
using Fiorello.Areas.Admin.Data;
using Fiorello.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;

namespace Fiorello.Areas.Admin.Controllers
{
   
    public class SliderController : BaseController
    {
        private readonly AppDbContext _dbContext;

        public SliderController(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public async Task<IActionResult> Index()
        {
            var slider = await _dbContext.Sliders
                .FirstOrDefaultAsync();

            return View(slider);
        }

        public async Task<IActionResult> Update()
        {
            var slider = await _dbContext.Sliders
                .FirstOrDefaultAsync();

            return View(new SliderUpdateDto
            {
                Title = slider.Title,
                Subtitle = slider.Subtitle,
                ImageUrl = slider.ImgUrl,
            });
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(SliderUpdateDto model)
        {
            var slider = await _dbContext.Sliders
                .FirstOrDefaultAsync();

            if (model.ImageUrl == "")
            {
                model.ImageUrl = slider.ImgUrl;
            }
            else
            {
                if (!ModelState.IsValid)
                {
                    return View(new SliderUpdateDto
                    {
                        Title = slider.Title,
                        Subtitle = slider.Subtitle,
                        ImageUrl = slider.ImgUrl,
                    });
                }

                if (!model.Image.IsImage())
                {
                    ModelState.AddModelError("Image", "Yalniz Shekil Kecin");

                    return View(new SliderUpdateDto
                    {
                        Title = slider.Title,
                        Subtitle = slider.Subtitle,
                        ImageUrl = slider.ImgUrl,
                    });
                }

                if (!model.Image.IsAllowedSize(2))
                {
                    ModelState.AddModelError("Image", "Sheklin Hecmi 1MB-dan Az Olmalidi");

                    return View(new SliderImageUpdateDto
                    {
                        ImageUrl = slider.ImgUrl,
                    });
                }
                var path = Path.Combine(Constants.RootPath, "img", slider.ImgUrl);

                if (System.IO.File.Exists(path))
                    System.IO.File.Delete(path);

                var unicalName = await model.Image.GenerateFile(Constants.RootPath);

                slider.ImgUrl = unicalName;
            }

            slider.Subtitle = model.Subtitle;
            slider.Title = model.Title;

            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
