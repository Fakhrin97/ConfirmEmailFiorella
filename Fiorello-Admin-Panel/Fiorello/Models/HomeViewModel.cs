namespace Fiorello.Models
{
    public class HomeViewModel
    {
        public List<Category> Category { get; set; } = new List<Category>();    
        public List<Product> Product { get; set; } = new List<Product>();
        public List<SliderImage> SliderImage { get; set; } = new List<SliderImage>();
        public Slider Slider { get; set; } = new Slider(); 
    }
}
