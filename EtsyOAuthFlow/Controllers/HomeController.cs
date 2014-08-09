using System.Web.Mvc;
using DevDefined.OAuth.Consumer;
using DevDefined.OAuth.Framework;

namespace TreasureGurusEtsy.Controllers
{
    public class HomeController : Controller
    {
        private const string RequestTokenUrl = @"https://openapi.etsy.com/v2/oauth/request_token";
        private const string UserAuthorizeUrl = @"https://www.etsy.com/oauth/signin";
        private const string AccessTokenUrl = @"https://openapi.etsy.com/v2/oauth/access_token";

        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Auth()
        {
            var scopes = Request.Form["scope"];
            if (scopes == null)
            {
                return RedirectToAction("Index");
            }

            //Temporarily store session scopes
            TempData["Scope"] = scopes;

            var session = CreateOAuthSession(scopes);

            var requestToken = session.GetRequestToken();
            //Temporarily store session to use to get access token
            TempData["RequestToken"] = requestToken;

            var authorizationLink = session.GetUserAuthorizationUrlForToken(requestToken);
            return Redirect(authorizationLink);
        }

        public ActionResult AuthResult()
        {
            if (!Request.QueryString.HasKeys())
            {
                return RedirectToAction("Index");
            }

            var scopes = (string)TempData["Scope"];
            var requestToken = (IToken) TempData["RequestToken"];

            var session = CreateOAuthSession(scopes);

            // Retrieve verify code
            var oauthVerifier = Request.QueryString["oauth_verifier"];

            var accessToken = session.ExchangeRequestTokenForAccessToken(requestToken, oauthVerifier);

            return View(accessToken);
        }

        private OAuthSession CreateOAuthSession(string scopes)
        {
            var context = new OAuthConsumerContext();
            context.ConsumerKey = System.Configuration.ConfigurationManager.AppSettings["ConsumerKey"];
            context.ConsumerSecret = System.Configuration.ConfigurationManager.AppSettings["ConsumerSecret"];
            context.SignatureMethod = SignatureMethod.HmacSha1;

            var callBackUrl = Url.Action("AuthResult", "Home", null, Request.Url.Scheme);

            var session = new OAuthSession(
                context,
                requestTokenUrl: RequestTokenUrl,
                userAuthorizeUrl: UserAuthorizeUrl,
                accessTokenUrl: AccessTokenUrl,
                callBackUrl: callBackUrl);

            session.WithQueryParameters(new { scope = scopes });

            return session;
        }
    }
}