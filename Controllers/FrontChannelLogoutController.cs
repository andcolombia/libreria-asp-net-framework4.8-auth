

using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Web;
using System.Web.Mvc;

namespace MvcDotNetClient.Controllers
{
    public class FrontChannelLogoutController : Controller
    {
        public ActionResult Index(string sid, string iss)
        {
            if (User.Identity.IsAuthenticated)
            {
                var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;
                var currentSid = userClaims.FindFirst("sid")?.Value;
                if (sid == currentSid)
                {
                    HttpContext.GetOwinContext().Authentication.SignOut(
                  OpenIdConnectAuthenticationDefaults.AuthenticationType,
                  CookieAuthenticationDefaults.AuthenticationType);
                }
            }
            return Redirect("~/");
        }
    }
}