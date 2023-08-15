using Microsoft.Owin;
using Owin;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Notifications;
using System;
using System.Threading.Tasks;
using System.Security.Claims;

[assembly: OwinStartup(typeof(MvcDotNetClient.Startup))]

namespace MvcDotNetClient
{
    public class Startup
    {
        // The Client ID is used by the application to uniquely identify itself.
        string clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];

        string clientSecret = System.Configuration.ConfigurationManager.AppSettings["ClientSecret"];

        // RedirectUri is the URL where the user will be redirected to after they sign in.
        string redirectUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];

        // RedirectUri is the URL where the user will be redirected to after they sign in.
        string redirectUriLogout = System.Configuration.ConfigurationManager.AppSettings["redirectUriLogout"];

        // Tenant is the tenant ID
        static string tenant = System.Configuration.ConfigurationManager.AppSettings["Tenant"];

        // Authority is the URL for authority
        string authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["Authority"], tenant);

        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                AuthenticationType = "Cookies",
                CookieSameSite = SameSiteMode.None
            });
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    Authority = authority,
                    RedirectUri = redirectUri,
                    ClientSecret = clientSecret,

                    // PostLogoutRedirectUri is the page that users will be redirected to after sign-out.
                    PostLogoutRedirectUri = redirectUriLogout,
                    Scope = "openid email",
                    UseTokenLifetime = false,
                    SignInAsAuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,

                    // ResponseType is set to request the id_token - which contains basic information about the signed-in user
                    ResponseType = OpenIdConnectResponseType.CodeIdTokenToken,

                    // ValidateIssuer set to false to allow personal and work accounts from any organization to sign in to your application
                    // To only allow users from a single organizations, set ValidateIssuer to true and 'tenant' setting in web.config to the tenant name
                    // To allow users from only a list of specific organizations, set ValidateIssuer to true and use ValidIssuers parameter
                    TokenValidationParameters = new TokenValidationParameters()
                    {
                        NameClaimType = "name",
                        RoleClaimType = "role",
                        ValidateIssuer = false
                    },


                    // OpenIdConnectAuthenticationNotifications configures OWIN to send notification of failed authentications to OnAuthenticationFailed method
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = OnAuthenticationFailed,
                        SecurityTokenValidated = notification =>
                        {
                            notification.AuthenticationTicket.Identity.AddClaim(new Claim("id_token", notification.ProtocolMessage.IdToken));
                            notification.AuthenticationTicket.Identity.AddClaim(new Claim("access_token", notification.ProtocolMessage.AccessToken));
                            return Task.FromResult(0);
                        },
                        RedirectToIdentityProvider = n => {
                            if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                            {
                                var idTokenHint =
                                    n.OwinContext.Authentication.User.FindFirst("id_token").Value;
                                n.ProtocolMessage.IdTokenHint = idTokenHint;
                            }
                            else if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                            {
                                if (n.Request.Path.Value == "/Home/SignIn" || n.Request.Path.Value == "/Claims/Personalizar")
                                {
                                    var stateQueryString = n.ProtocolMessage.State.Split('=');
                                    var protectedState = stateQueryString[1];
                                    var state = n.Options.StateDataFormat.Unprotect(protectedState);
                                    if (state.Dictionary.ContainsKey("login_hint"))
                                    {
                                        n.ProtocolMessage.LoginHint = state.Dictionary["login_hint"];
                                    }
                                    if (state.Dictionary.ContainsKey("acr_values"))
                                    {
                                        n.ProtocolMessage.AcrValues = state.Dictionary["acr_values"];
                                    }
                                }
                                else
                                {
                                    n.ProtocolMessage.Prompt = "none";
                                }


                            }
                            return Task.FromResult(0);
                        }
                    }
                }
            );
        }

        /// <summary>
        /// Handle failed authentication requests by redirecting the user to the home page with an error in the query string
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            if (context.Exception.Message.Contains("login_required"))
            {
                context.Response.Redirect("/Home/SignOut");
                context.HandleResponse();
            }
            else
            {
                context.HandleResponse();
                context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            }
            return Task.FromResult(0);
        }
    }
}
