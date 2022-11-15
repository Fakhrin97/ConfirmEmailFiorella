namespace Fiorello.Models
{
    public class BasketViewModel
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public int Price { get; set; }
        public Category? Category { get; set; }
        public int CategoryId { get; set; }
        public string? ImageUrl { get; set; }
        public double? DiscountDegree { get; set; }
        public int Count { get; set; }  
    }
}
