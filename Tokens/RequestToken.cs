using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.OAuth.Jira.Tokens
{
    public class RequestToken : JiraToken
    {
        /// <summary>
        /// Gets or sets a property bag for common authentication properties.
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}