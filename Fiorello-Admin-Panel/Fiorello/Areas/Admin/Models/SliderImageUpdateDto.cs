namespace Fiorello.Areas.Admin.Models
{
    public class SliderImageUpdateDto
    {
        public string ImageUrl { get; set; } = string.Empty;
        public IFormFile Image { get; set; }    
    }
}
