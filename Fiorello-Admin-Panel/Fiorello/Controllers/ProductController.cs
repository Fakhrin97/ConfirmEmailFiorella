using Fiorello.DAL;
using Fiorello.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Fiorello.Controllers
{
    public class ProductController : Controller
    {
        private readonly AppDbContext _dbContext;
        private int _prductCount;

        public ProductController(AppDbContext dbContext)
        {
            _dbContext = dbContext;
            _prductCount = dbContext.Products.Count();
        }

        public async Task<IActionResult> Index()
        {
            ViewBag.prductCount = _prductCount;

            List<Product> products = await _dbContext.Products
                .Include(p=>p.Category)
                .Take(4)
                .ToListAsync();

            return View(products);
        }

        public async Task<IActionResult> Details(int id)
        {
            if (id == null) return NotFound();

            Product product = await _dbContext.Products
                .SingleOrDefaultAsync(pId => pId.Id == id);

            if (product == null) return NotFound();

            return View(product);
        }

        [HttpPost]
        public async Task<IActionResult> Partial(int skip)
        {
            if (skip >= _prductCount)
                return BadRequest();

            List<Product> products = await _dbContext.Products
                .Include(p => p.Category)
                .Skip(skip)
                .Take(4)
                .ToListAsync();

            return PartialView("_ProductPartialView", products);
        }

    }
}
