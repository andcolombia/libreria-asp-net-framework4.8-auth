using IdentityModel.Client;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MvcDotNetClient.Controllers
{
    [Authorize]
    public class ClaimsController : AsyncController
    {
        /// <summary>
        /// Add user's claims to viewbag
        /// </summary>
        /// <returns></returns>
        public async Task<ActionResult> IndexAsync()
        {
            var httpClient = new HttpClient();
            var userInfo = new UserInfoRequest();

            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;

            //You get the user's first and last name below:
            ViewBag.Name = userClaims?.FindFirst("aud")?.Value;

            // The 'preferred_username' claim can be used for showing the username
            ViewBag.Username = userClaims?.FindFirst("aud")?.Value;

            // The subject/ NameIdentifier claim can be used to uniquely identify the user across the web
            ViewBag.Subject = userClaims?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            // TenantId is the unique Tenant Id - which represents an organization in Azure AD
            ViewBag.TenantId = userClaims?.FindFirst("iss")?.Value;

            userInfo.Address = ConfigurationManager.AppSettings["Authority"] + "/connect/userinfo";
            userInfo.Token = userClaims?.FindFirst("access_token")?.Value;

            var userInfoProfile = await httpClient.GetUserInfoAsync(userInfo);

            ViewBag.userClaims = userInfoProfile.Claims;

            return View();

        }

        public async Task PersonalizarAsync()
        {
            var authenticationProperties = new AuthenticationProperties();
            var httpClient = new HttpClient();
            var userInfo = new UserInfoRequest();
            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;

            userInfo.Address = ConfigurationManager.AppSettings["Authority"] + "/connect/userinfo";
            userInfo.Token = userClaims?.FindFirst("access_token")?.Value;
            var userInfoProfile = await httpClient.GetUserInfoAsync(userInfo);

            foreach(var claim in userInfoProfile.Claims)
            {
                if(claim.Type == "given_name")
                {
                    authenticationProperties.Dictionary.Add("login_hint", claim.Value);
                }
            }

            authenticationProperties.Dictionary.Add("acr_values", string.Format("action:manage"));
            var auth = HttpContext.GetOwinContext().Authentication;
            auth.Challenge(authenticationProperties);
        }
    }
}
