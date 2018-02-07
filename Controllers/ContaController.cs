using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Autenticacao_EF_Cookie.Models;
using Autenticacao_EF_Cookie.Repositorio;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Autenticacao_EF_Cookie.Controllers
{
    [AllowAnonymous]
    public class ContaController : Controller
    {
        readonly AutenticacaoContexto _contexto;

        public ContaController(AutenticacaoContexto contexto)
        {
            _contexto = contexto;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(Usuario usuario)
        {
            try
            {
                Usuario user = _contexto.Usuarios.FirstOrDefault(c => c.Email == usuario.Email || 
                                                                    c.Senha == usuario.Senha );

                if (user != null)
                {
                    List<Claim> claims = GetClaims(user); //Get the claims from the headers or db or your user store
                    if (null != claims)
                    {
                        var claimsIdentity = new ClaimsIdentity(
                            claims, CookieAuthenticationDefaults.AuthenticationScheme
                        );

                        HttpContext.SignInAsync( CookieAuthenticationDefaults.AuthenticationScheme, 
                                    new ClaimsPrincipal(claimsIdentity));

                        return RedirectToAction("Index", "Home");
                    }
                }

                return View();
            }
            catch (System.Exception ex)
            {
                ModelState.AddModelError("", ex.Message);
                return View(usuario);
            }

            
        }

        private List<Claim> GetClaims(Usuario usuario)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Email, usuario.Email));
            claims.Add(new Claim(ClaimTypes.Name, usuario.Nome));

            foreach (var item in usuario.UsuariosPermissoes)
            {
                claims.Add(new Claim(ClaimTypes.Role, item.Permissao.Nome));
            }

            return claims;
        }
    }
}