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
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using JWTBoilerplate.Core.Models;
using JWTBoilerplate.Core.Models.AccountViewModels;
using JWTBoilerplate.Core.Services;
using JWTBoilerplate.Dal.Interface;

namespace HWGBOTC.API.core.Controllers
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/member")]
    public class MemberApiController : Controller
    {

        private readonly iMemberService _memberservice;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender _emailSender;

        public MemberApiController(IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            iMemberService memberservice,
            IEmailSender emailSender)
        {
            _configuration = configuration;
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _memberservice = memberservice;
            _emailSender = emailSender;
        }

        [AllowAnonymous]
        [HttpPost("Login")]
        public async Task<IActionResult> Post([FromBody]LoginViewModel request)
        {
            if (ModelState.IsValid)
            {
                //get user from request 

                var user = await _userManager.FindByEmailAsync(request.Email);
                var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);

                if (!result.Succeeded)
                {
                    if (result.RequiresTwoFactor)
                    {
                        return BadRequest("Requires two factor");
                    }
                    else if (result.IsLockedOut)
                    {
                        return BadRequest("User is locked out");
                    }
                    else if (result.IsNotAllowed)
                    {
                        return BadRequest("User is not verified , please check confirmation email");
                    }
                    else
                    {
                        return BadRequest("Username and password mismatched");
                    }
                }

                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, request.Email)
                };

                var token = GenerateToken(claims);
                var refreshtoken = GenerateRefreshToken();

                _memberservice.UpdateRefreshToken(user.UserName, refreshtoken); //create initial refresh token 

                //get member ID 
                long memberId = _memberservice.GetMemberIdByUsername(user.UserName);

                return Ok(new
                {
                    id = memberId,
                    username = user.UserName,
                    firstname = "",
                    lastname = "",
                    token = token,
                    refreshtoken = refreshtoken
                });
            }

            return BadRequest(ModelState);
        }


        [AllowAnonymous]
        [HttpPost("Register")]
        public async Task<IActionResult> Post([FromBody]RegisterViewModel request)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = request.Email, Email = request.Email };
                var result = await _userManager.CreateAsync(user, request.Password);

                //check role exist 
                bool chkRoleAdmin = await _roleManager.RoleExistsAsync("Member");

                if (!chkRoleAdmin)
                {
                    var role = new IdentityRole();
                    role.Name = "Member";
                    await _roleManager.CreateAsync(role);
                }

                if (result.Succeeded)
                {
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);

                    await _emailSender.SendEmailAsync(request.Email, "Confirm your email",
                             $"Please confirm your account by <a href='{System.Net.WebUtility.HtmlEncode(callbackUrl)}'>clicking here</a>.");

                    //add role to user 
                    await _userManager.AddToRoleAsync(user, "Member");

                    //add member information 
                    _memberservice.CreateMemberRecord(user.Id, request.Email, request.Name, request.IdentityNumber, request.IdentityType);

                    return Ok(new
                    {
                        id = user.Id,
                        username = user.UserName
                    });
                }
                else
                {
                    return BadRequest(result.Errors);
                }
            }

            return BadRequest(ModelState);
        }

        [AllowAnonymous]
        [HttpPost("ResendEmail")]
        public async Task<IActionResult> Post([FromBody]ResendViewModel request)
        {
            if (ModelState.IsValid)
            {
                //get user from email 
                var user = await _userManager.FindByEmailAsync(request.Email);

                if (user != null)
                {
                    //revoke previous confirmation token 
                    await _userManager.UpdateSecurityStampAsync(user);

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = System.Net.WebUtility.UrlEncode(code);
                    //var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
                    var callbackUrl = string.Format(@"
                                           {0}confirmemail?email={1}&code={2}
                                        ", _configuration["Settings:MemberDomain"], request.Email, code);


                    await _emailSender.SendEmailAsync(request.Email, "Confirm your email",
                            $"Please confirm your account by <a href='{System.Net.WebUtility.HtmlEncode(callbackUrl)}'>clicking here</a>.");

                    return Ok(new
                    {
                    });
                }
                else
                {
                    return BadRequest("User Not found");
                }
            }

            return BadRequest(ModelState);
        }


        [AllowAnonymous]
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> Get(string email, string code)
        {
            if (ModelState.IsValid)
            {
                //get user from email 
                var user = await _userManager.FindByEmailAsync(email);

                if (user != null)
                {

                    var result = await _userManager.ConfirmEmailAsync(user, code);

                    if (result.Succeeded)
                    {
                        return Ok(new
                        {
                        });
                    }
                    else
                    {
                        return BadRequest(result.Errors);
                    }

                }
                else
                {
                    return BadRequest("User Not found");
                }
            }

            return BadRequest(ModelState);
        }


        private string GenerateToken(IEnumerable<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecurityKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var jwt = new JwtSecurityToken(
                issuer: _configuration["JWTissuer"],
                audience: _configuration["JWTaudience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(jwt); //the method is called WriteToken but returns a string
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(_configuration["SecurityKey"])),
                ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        [AllowAnonymous]
        [HttpPost("RefreshToken")]
        public IActionResult Refresh([FromBody]RefreshtokenApiModel request)
        {
            var principal = GetPrincipalFromExpiredToken(request.token);
            var username = principal.Identity.Name;
            var savedRefreshToken = _memberservice.GetRefreshToken(username); //retrieve the refresh token from a data store
            if (savedRefreshToken != request.refreshToken)
                throw new SecurityTokenException("Invalid refresh token");

            var newJwtToken = GenerateToken(principal.Claims);
            var newRefreshToken = GenerateRefreshToken();
            _memberservice.UpdateRefreshToken(username, newRefreshToken);

            return Ok(new
            {
                token = newJwtToken,
                refreshtoken = newRefreshToken
            });
        }
    }
}