using Fiorello.DAL;
using Fiorello.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Fiorello.ViewComponents
{
    public class BioViewComponent : ViewComponent
    {
        private readonly AppDbContext _dbContext;

        public BioViewComponent(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<IViewComponentResult> InvokeAsync()
        {
            List<Bio> bios = await _dbContext.Bios
                .ToListAsync();

            return View(bios);
        }
    }
}
