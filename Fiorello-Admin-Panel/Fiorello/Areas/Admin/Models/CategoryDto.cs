using System.ComponentModel.DataAnnotations;

namespace Fiorello.Areas.Admin.Models
{
    public class CategoryDto
    {
        public string Description { get; set; }

        [Required, MaxLength(20)]
        public string? Name { get; set; }
    }
}
