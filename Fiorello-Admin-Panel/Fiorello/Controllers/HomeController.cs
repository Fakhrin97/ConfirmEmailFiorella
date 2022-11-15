using Fiorello.DAL;
using Fiorello.Models;
using Fiorello.Services.EmailServices;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Linq;

namespace Fiorello.HomeControllers
{
    public class HomeController : Controller
    {
        private readonly AppDbContext _dbContext;
       

        public HomeController(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public async Task<IActionResult> Index()
        {

            Slider slider = await _dbContext.Sliders
                .SingleAsync();

            List<SliderImage> sliderImages = await _dbContext.SliderImages
                .ToListAsync();

            List<Category> categories = await _dbContext.Categories
                .ToListAsync();

            List<Product> products = await _dbContext.Products
                .Include(pro => pro.Category)
                .ToListAsync();

            var homeViewModel = new HomeViewModel
            {
                Slider = slider,
                SliderImage = sliderImages,
                Category = categories,
                Product = products,
            };

            return View(homeViewModel);
        }

        public async Task<IActionResult> SearchProducts(string searchPrdouctName)
        {
            if (string.IsNullOrEmpty(searchPrdouctName))
                return NoContent();

            List<Product> products = await _dbContext.Products
                .Where(p => p.Name.ToLower().Contains(searchPrdouctName.ToLower()))
                .ToListAsync();

            return PartialView("_SearchProductListPartialView", products);
        }

        public async Task<IActionResult> AddToBasket(int id)
        {

            var product = await _dbContext.Products
                .Where(p => p.Id == id)
                .Include(p => p.Category)
                .FirstOrDefaultAsync();

            if (product == null)
                return NotFound();

            var productJson = Request.Cookies["basket"];
            List<BasketViewModel> products = null;

            if (productJson != null)
                products = JsonConvert.DeserializeObject<List<BasketViewModel>>(productJson);

            if (products != null)
            {
                var existProduct = products.Where(x => x.Id == product.Id).SingleOrDefault();

                if (existProduct != null) existProduct.Count++;
                else
                {
                    products.Add(new BasketViewModel
                    {
                        Id = product.Id,
                        Count = 1,
                    });
                }
            }
            else
            {
                products = new List<BasketViewModel>
                {
                    new BasketViewModel
                    {
                        Id = product.Id,
                        Count = 1
                    }
                };
            }


            var prductJson = JsonConvert
                .SerializeObject(products, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });

            Response.Cookies.Append("basket", prductJson);
            return NoContent();
        }

        public async Task<IActionResult> Basket()
        {
            var productJson = Request.Cookies["basket"];
            if (productJson == null) return BadRequest();

            List<BasketViewModel> products = JsonConvert
                .DeserializeObject<List<BasketViewModel>>(productJson);

            foreach (var product in products)
            {
                var existproduct = await _dbContext.Products
                    .Include(x => x.Category)
                    .SingleOrDefaultAsync(x => x.Id == product.Id);

                if (product != null)
                {
                    product.ImageUrl = existproduct.ImageUrl;
                    product.DiscountDegree = existproduct.DiscountDegree;
                    product.Name = existproduct.Name;
                    product.Price = existproduct.Price;
                    product.Category = existproduct.Category;
                }

            }

            return View(products);
        }
    }
}
