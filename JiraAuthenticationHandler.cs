using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;
using AspNet.Security.OAuth.Jira.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;
using RestSharp;
using RestSharp.Authenticators;
using RestSharp.Authenticators.OAuth;

namespace AspNet.Security.OAuth.Jira
{
    public class JiraAuthenticationHandler : RemoteAuthenticationHandler<JiraOptions>
    {
        public JiraAuthenticationHandler(IOptionsMonitor<JiraOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
            
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        // Supports naming convention("Events") which is used by custom authentication handlers 
        protected new JiraEvents Events
        {
            get => (JiraEvents)base.Events;
            set => base.Events = value;
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new JiraEvents());

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            var redirectUri = BuildRedirectUri(Options.CallbackPath);
            var requestToken = await GetOAuth1RequestTokenAsync(redirectUri, properties);
            var jiraAuthenticationUri = $"{Options.AuthenticationEndpoint}?oauth_token={requestToken.Token}&{redirectUri}";

            SaveRequestTokenToCookie(requestToken);

            var redirectContext = new RedirectContext<JiraOptions>(Context, Scheme, Options, properties, jiraAuthenticationUri);
            await Events.RedirectToAuthorizationEndpoint(redirectContext);
        }

        /// <summary>
        /// Authenticate the user identity with the identity provider.
        ///
        /// The method process the request on the endpoint defined by CallbackPath.
        /// </summary>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var requestToken = GetRequestTokenFromCookie();

            var validationErrorDescription = ValidateRequest(requestToken, Request.Query);
            if (!string.IsNullOrEmpty(validationErrorDescription))
            {
                return HandleRequestResult.Fail(validationErrorDescription);
            }

            RemoveRequestTokenFromCookie();

            var accessToken = await GetOAuth1AccessTokenAsync(requestToken, Request.Query["oauth_verifier"]);

            var properties = requestToken.Properties;
            SaveAccessTokenToProperties(accessToken, properties);
            
            var ticket = await CreateTicketAsync(properties, accessToken, null);

            return HandleRequestResult.Success(ticket);
        }

        private void SaveAccessTokenToProperties(AccessToken accessToken, AuthenticationProperties properties)
        {
            if (Options.SaveTokens)
            {
                properties.StoreTokens(new[]
                {
                    new AuthenticationToken {Name = "access_token", Value = accessToken.Token},
                    new AuthenticationToken {Name = "access_token_secret", Value = accessToken.TokenSecret}
                });
            }
        }

        private static string ValidateRequest(RequestToken requestToken, IQueryCollection query)
        {
            if (requestToken == null)
            {
                return "Invalid state cookie.";
            }

            var returnedToken = query["oauth_token"];
            if (StringValues.IsNullOrEmpty(returnedToken))
            {
                return "Missing oauth_token";
            }

            if (!string.Equals(returnedToken, requestToken.Token, StringComparison.Ordinal))
            {
                return "Unmatched token";
            }

            if (StringValues.IsNullOrEmpty(query["oauth_verifier"]))
            {
                return "Missing or blank oauth_verifier";
            }

            return null;
        }

        private async Task<AccessToken> GetOAuth1AccessTokenAsync(RequestToken requestToken,
            StringValues oauthVerifier)
        {
            var oAuth1Authenticator = OAuth1Authenticator.ForAccessToken(Options.ConsumerKey, Options.ConsumerSecret, requestToken.Token, requestToken.TokenSecret, oauthVerifier);
            oAuth1Authenticator.SignatureMethod = OAuthSignatureMethod.RsaSha1;
            var client = new RestClient(Options.AccessTokenEndpoint)
            {
                Authenticator = oAuth1Authenticator
            };

            var request = new RestRequest(Method.POST);
            var response = await client.ExecuteTaskAsync(request);

            var qs = HttpUtility.ParseQueryString(response.Content);

            var result = new AccessToken()
            {
                Token = qs["oauth_token"],
                TokenSecret = qs["oauth_token_secret"]
            };

            return result;
        }

        private async Task<RequestToken> GetOAuth1RequestTokenAsync(string callBackUri, AuthenticationProperties properties)
        {
            var authenticator = OAuth1Authenticator.ForRequestToken(Options.ConsumerKey, Options.ConsumerSecret, callBackUri);
            authenticator.SignatureMethod = OAuthSignatureMethod.RsaSha1;
            var client = new RestClient(Options.RequestTokenEndpoint)
            {
                Authenticator = authenticator
            };

            var request = new RestRequest(Method.POST);
            var response = await client.ExecuteTaskAsync(request);

            var qs = HttpUtility.ParseQueryString(response.Content);

            var result = new RequestToken()
            {
                Properties = properties,
                Token = qs["oauth_token"],
                TokenSecret = qs["oauth_token_secret"]
            };

            return result;
        }

        private async Task<AuthenticationTicket> CreateTicketAsync(
            AuthenticationProperties properties, AccessToken token, JObject user)
        {
            var identity = new ClaimsIdentity(ClaimsIssuer);

            foreach (var action in Options.ClaimActions)
            {
                action.Run(user, identity, ClaimsIssuer);
            }

            var context = new JiraCreatingTicketContext(Context, Scheme, Options, new ClaimsPrincipal(identity), properties, token.Token, token.TokenSecret, user);
            await Events.CreatingTicket(context);

            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }

        private void RemoveRequestTokenFromCookie()
        {
            var cookieOptions = Options.StateCookie.Build(Context, Clock.UtcNow);

            Response.Cookies.Delete(Options.StateCookie.Name, cookieOptions);
        }

        private RequestToken GetRequestTokenFromCookie()
        {
            var protectedRequestToken = Request.Cookies[Options.StateCookie.Name];

            var requestToken = Options.StateDataFormat.Unprotect(protectedRequestToken);
            return requestToken;
        }

        private void SaveRequestTokenToCookie(RequestToken requestToken)
        {
            var cookieOptions = Options.StateCookie.Build(Context, Clock.UtcNow);

            Response.Cookies.Append(Options.StateCookie.Name, Options.StateDataFormat.Protect(requestToken), cookieOptions);
        }
    }
}