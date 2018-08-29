using System;
using System.Collections.Generic;
using System.Text;
using JWTBoilerplate.Dal.Models;

namespace JWTBoilerplate.Dal.Interface
{
    public interface iProductService
    {
        List<Products> GetProducts();
    }
}
