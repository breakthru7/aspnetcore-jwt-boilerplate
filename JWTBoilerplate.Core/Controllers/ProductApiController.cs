using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using JWTBoilerplate.Dal.Interface; 

namespace JWTBoilerplate.Core.Controllers
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/products")]
    public class ProductApiController : Controller
    {
        private readonly iProductService _productService;

        public ProductApiController(iProductService productservice)
        {
            _productService = productservice;
        }

        //sample API to retrieve products that is secured with JWT authentication 

        [HttpGet("GetProducts")]
        public IActionResult GetProducts()
        {
            try
            {
                var products = _productService.GetProducts();

                return Ok(products);
            }
            catch(Exception ex)
            {
                return BadRequest(ex.Message);
            }

        }
    }
}