using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;

namespace MvcDotNetClient.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";
            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
        /// <summary>
        /// Send an OpenID Connect sign-in request.
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public void SignIn(FormCollection formCollection)
        {
            if (!Request.IsAuthenticated)
            {
                string _tipoIdentificacion = formCollection["TipoIdentificacion"];
                string _identificacion = formCollection["Identificacion"];
                string _accion = formCollection["Accion"];
                string redirectUri = ConfigurationManager.AppSettings["redirectUri"];
                var authenticationProperties = new AuthenticationProperties();
                if(!string.IsNullOrEmpty(_tipoIdentificacion) && !string.IsNullOrEmpty(_identificacion))
                    authenticationProperties.Dictionary.Add("login_hint", string.Format("{0},{1}", _tipoIdentificacion, _identificacion));
                if (!string.IsNullOrEmpty(_accion))
                {
                    if ( _accion == "register")
                    {
                        string _nivel = "loa:2";
                        if (_tipoIdentificacion == "EM")
                            _nivel = "loa:1";
                        authenticationProperties.Dictionary.Add("acr_values", string.Format("action:{0} {1}", _accion, _nivel));
                    }
                    else
                        authenticationProperties.Dictionary.Add("acr_values", string.Format("action:{0}", _accion));
                }
                    
                authenticationProperties.RedirectUri = redirectUri;
                var auth = HttpContext.GetOwinContext().Authentication;
                auth.Challenge(authenticationProperties);
            }
        }

        /// <summary>
        /// Send an OpenID Connect sign-out request.
        /// </summary>
        public ActionResult SignOut()
        {
            if (Request.GetOwinContext().Authentication.User.Identity.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.SignOut(
                   OpenIdConnectAuthenticationDefaults.AuthenticationType,
                   CookieAuthenticationDefaults.AuthenticationType);
            }
            return Redirect("~/");
        }
    }
}