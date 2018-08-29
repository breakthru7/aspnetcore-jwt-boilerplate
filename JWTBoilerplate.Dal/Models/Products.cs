using System;
using System.Collections.Generic;

namespace JWTBoilerplate.Dal.Models
{
    public partial class Products
    {
        public long Id { get; set; }
        public string Name { get; set; }
        public string Isbn { get; set; }
        public DateTime? Created { get; set; }
    }
}
