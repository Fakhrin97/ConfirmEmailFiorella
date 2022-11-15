using Fiorello.Areas.Admin.Data;
using Fiorello.Areas.Admin.Models;
using Fiorello.DAL;
using Fiorello.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Fiorello.Areas.Admin.Controllers
{
 
    public class SliderImageController : BaseController
    {
        private readonly AppDbContext _dbContext;

        public SliderImageController(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<IActionResult> Index()
        {
            List<SliderImage> sliderImages = await _dbContext.SliderImages
               .ToListAsync();

            return View(sliderImages);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(SliderImageDto model)
        {
            if (!ModelState.IsValid)
                return View();

            if (!model.Image.IsImage())
            {
                ModelState.AddModelError("Image", "Yalniz Shekil Kecin");
                return View();
            }

            if (!model.Image.IsAllowedSize(2))
            {
                ModelState.AddModelError("Image", "Sheklin Hecmi 1MB-dan Az Olmalidi");
                return View();
            }

            var unicalName = await model.Image.GenerateFile(Constants.RootPath);

            await _dbContext.SliderImages.AddAsync(new SliderImage
            {
                Url = unicalName,
            });
            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Update(int? id)
        {
            if (id == null)
                return NotFound();

            var image = await _dbContext.SliderImages.FindAsync(id);

            if (image == null)
                return NotFound();

            return View(new SliderImageUpdateDto
            {
                ImageUrl = image.Url,
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(int? id, SliderImageUpdateDto sliderImage)
        {
            if (id == null)
                return NotFound();

            var image = await _dbContext.SliderImages.FindAsync(id);

            if (image == null)
                return NotFound();

            if (image.Id != id)
                return BadRequest();

            if (!ModelState.IsValid)
            {
                return View(new SliderImageUpdateDto
                {
                    ImageUrl = image.Url,
                });
            }

            if (!sliderImage.Image.IsImage())
            {
                ModelState.AddModelError("Image", "Yalniz Shekil Kecin");

                return View(new SliderImageUpdateDto
                {
                    ImageUrl = image.Url,
                });
            }

            if (!sliderImage.Image.IsAllowedSize(2))
            {
                ModelState.AddModelError("Image", "Sheklin Hecmi 1MB-dan Az Olmalidi");

                return View(new SliderImageUpdateDto
                {
                    ImageUrl = image.Url,
                });
            }

            var path = Path.Combine(Constants.RootPath , "img" , image.Url); 
            
            if(System.IO.File.Exists(path))
                System.IO.File.Delete(path);

            var unicalName = await sliderImage.Image.GenerateFile(Constants.RootPath);
            image.Url = unicalName;  
            
            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
                return NotFound();

            var image = await _dbContext.SliderImages.FindAsync(id);

            if (image == null)
                return NotFound();

            if (image.Id != id)
                return BadRequest();

            var path = Path.Combine(Constants.RootPath, "img", image.Url);

            if (System.IO.File.Exists(path))
                System.IO.File.Delete(path);

            _dbContext.SliderImages.Remove(image);
            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        public IActionResult CreateMulti()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateMulti(SliderImageMultiDto model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            foreach (var image in model.Images)
            {
                if (!image.IsImage())
                {
                    ModelState.AddModelError("Images", "Yalniz Shekil Kecin");

                    return View();
                }

                if (!image.IsAllowedSize(2))
                {
                    ModelState.AddModelError("Images", "Sheklin Hecmi 1MB-dan Az Olmalidi");

                    return View();
                }

                var unicalName = await image.GenerateFile(Constants.RootPath);
                await _dbContext.SliderImages.AddAsync(new SliderImage
                {
                    Url = unicalName,
                });

            }

            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
