using Fiorello.Areas.Admin.Models;
using Fiorello.DAL;
using Fiorello.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Data;

namespace Fiorello.Areas.Admin.Controllers
{
   
    public class CategoryController : BaseController
    {
        private readonly AppDbContext _dbContext;

        public CategoryController(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<IActionResult> Index()
        {
            List<Category> categories =  await _dbContext.Categories
                .ToListAsync();

            return View(categories);
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
                return NotFound();

            Category category = await _dbContext.Categories
                 .FindAsync(id);
            if (category == null)
                return NotFound();    
            
            return View(category);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CategoryDto category)
        {
            if (!ModelState.IsValid)
                return View();

            var existName = await _dbContext.Categories
                .AnyAsync(c => c.Name.ToLower().Equals(category.Name.ToLower()));

            if (existName)
            {
                ModelState.AddModelError("name", "Eyni Add Category Artiq Bazada Movcuddur");
                return View();  
            }

            var categoryEntity = new Category
            {
                Name=category.Name,
                Description=category.Description,

            };

            await _dbContext.AddAsync(categoryEntity);
            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Update(int? id)
        {
            if(id == null)
                return NotFound();

            Category category= await _dbContext.Categories.FindAsync(id);
            if (category == null)
                return BadRequest();

            return View(new UpdateCategoryDto
            {
                Name = category.Name,
                Description = category.Description
            });            
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(int? id , UpdateCategoryDto model)
        {
            if (id == null)
                return NotFound();

            Category category = await _dbContext.Categories.FindAsync(id);
            if (category == null)
                return BadRequest();

            if (category.Id != id)
                return BadRequest();

            var existName = await _dbContext.Categories
                .AnyAsync(c=>c.Name.ToLower()==model.Name.ToLower() && c.Id!=id);   

            if (existName)
            {
                ModelState.AddModelError("Name", "Eyni Adda Categoriniz Var");
                return View();
            }

            category.Name = model.Name; 
            category.Description = model.Description;

            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
       
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
                return NotFound();

            var category = await _dbContext.Categories.FindAsync(id);

            if (category == null)
                return NotFound();

            _dbContext.Categories.Remove(category);
            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
