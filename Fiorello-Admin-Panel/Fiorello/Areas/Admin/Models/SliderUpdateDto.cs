namespace Fiorello.Areas.Admin.Models
{
    public class SliderUpdateDto
    {
        public string Title { get; set; }   
        public string Subtitle { get; set; }
        public string ImageUrl { get; set; } = string.Empty;
        public IFormFile Image { get; set; }    

    }
}
