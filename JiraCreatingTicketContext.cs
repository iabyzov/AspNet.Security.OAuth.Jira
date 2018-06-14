using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Jira
{
    public class JiraCreatingTicketContext : ResultContext<JiraOptions>
    {
        public JiraCreatingTicketContext(
            HttpContext context,
            AuthenticationScheme scheme,
            JiraOptions options,
            ClaimsPrincipal principal,
            AuthenticationProperties properties,
            string accessToken,
            string accessTokenSecret, 
            JObject user)
            : base(context, scheme, options)
        {
            Principal = principal;
            Properties = properties;
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
            User = user;
        }

        /// <summary>
        /// Gets the Jira access token
        /// </summary>
        public string AccessToken { get; }

        /// <summary>
        /// Gets the Jira access token secret
        /// </summary>
        public string AccessTokenSecret { get; }

        /// <summary>
        /// Gets the JSON-serialized user or an empty
        /// <see cref="JObject"/> if it is not available.
        /// </summary>
        public JObject User { get; set; }
    }
}