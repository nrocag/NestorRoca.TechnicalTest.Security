namespace NestorRoca.TechnicalTest.Security.Api.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Text;

    [Route("[Controller]/v1")]
    [ApiController]
    public class SecurityController : ControllerBase
    {
        private const string secret = "00CC73CF-276E-461E-B5CB-55B2C3D19BCB";

        private readonly List<User> users = new List<User>
        {
            new User { Id = 1, Role="Administrador", FirstName = "Administrador", LastName = "Del sistema", Username = "admin", Password = "admin" },
            new User { Id = 2, Role="NoEsAdministrador", FirstName = "NoEsAdministrador", LastName = "Del sistema", Username = "noadmin", Password = "noadmin" }
        };

        [HttpGet]
        [AllowAnonymous]
        public ActionResult Index()
        {
            return this.Ok("Sistema de seguridad");
        }

        [HttpPost]
        [AllowAnonymous]
        public ActionResult<User> Authenticate([FromBody]Login login)
        {
            ActionResult actionResult;

            try
            {
                User user = this.users.SingleOrDefault(x => x.Username == login.Username && x.Password == login.Password);

                if (user == null)
                {
                    actionResult = this.NotFound("Usuario o contraseña invalido");
                }
                else
                {
                    JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                    byte[] key = Encoding.ASCII.GetBytes(secret);
                    SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(new Claim[]
                        {
                        new Claim(ClaimTypes.Name, user.FirstName),
                        new Claim(ClaimTypes.Role, user.Role)
                        }),
                        Expires = DateTime.UtcNow.AddDays(1),
                        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                    };

                    SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
                    user.Token = tokenHandler.WriteToken(token);
                    actionResult = this.Ok(user.WithoutPassword());
                }
            }
            catch (Exception ex)
            {
                //this.Instrumenter.LogError(ex, ex.Message);
                actionResult = this.StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }

            return actionResult;
        }
    }
}