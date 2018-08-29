using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using JWTBoilerplate.Dal.Models;
using Dapper; 

namespace JWTBoilerplate.Dal.Services
{
    public class ProductService
    {
        private jwtboilerplatedbContext _context;
        private IConfiguration _configuration;

        public ProductService() { }

        public ProductService(jwtboilerplatedbContext context, IConfiguration Configuration)
        {
            _context = context;
            _configuration = Configuration;
        }

        public List<Products> GetProducts()
        {
            List<Products> list = new List<Products>(); 

            var productEntities = _context.Database.GetDbConnection().Query<Products>(@"
                                        select * from products
                                    ");

            if(productEntities.Count() > 0)
            {
                list = productEntities.ToList();
            }

            return list; 
        }
        
    }
}
