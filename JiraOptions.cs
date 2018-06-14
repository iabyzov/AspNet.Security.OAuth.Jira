using System;
using AspNet.Security.OAuth.Jira.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Jira
{
    public class JiraOptions : RemoteAuthenticationOptions
    {
        private CookieBuilder _stateCookieBuilder;

        public JiraOptions()
        {
            CallbackPath = new PathString(JiraDefaults.CallbackPath);
            _stateCookieBuilder = new JiraCookieBuilder(this)
            {
                Name = JiraDefaults.CookieName,
                SecurePolicy = CookieSecurePolicy.SameAsRequest,
                HttpOnly = true,
                SameSite = SameSiteMode.Lax
            };
        }

        /// <summary>
        /// Determines the settings used to create the state cookie before the
        /// cookie gets added to the response.
        /// </summary>
        public CookieBuilder StateCookie
        {
            get => _stateCookieBuilder;
            set => _stateCookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// A collection of claim actions used to select values from the json user data and create Claims.
        /// </summary>
        public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();

        /// <summary>
        /// Gets or sets the <see cref="JiraEvents"/> used to handle authentication events.
        /// </summary>
        // Supports naming convention("Events") which is used by custom authentication options 
        public new JiraEvents Events
        {
            get => (JiraEvents)base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// Gets or sets the consumer key used to communicate with Jira.
        /// </summary>
        /// <value>The consumer key used to communicate with Jira.</value>
        public string ConsumerKey { get; set; }

        /// <summary>
        /// Gets or sets the consumer secret used to sign requests to Jira.
        /// </summary>
        /// <value>The consumer secret used to sign requests to Jira.</value>
        public string ConsumerSecret { get; set; }

        /// <summary>
        /// Gets or sets the URI the middleware will access to exchange the access OAuth1 token.
        /// </summary>
        public string AccessTokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the URI where the client will be redirected to authenticate.
        /// </summary>
        public string AuthenticationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the URI the middleware will access to exchange the request OAuth1 token.
        /// </summary>
        public string RequestTokenEndpoint { get; set; }

        public ISecureDataFormat<RequestToken> StateDataFormat { get; set; }

        private class JiraCookieBuilder : CookieBuilder
        {
            private readonly JiraOptions _jiraOptions;

            public JiraCookieBuilder(JiraOptions jiraOptions)
            {
                _jiraOptions = jiraOptions;
            }

            public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
            {
                var options = base.Build(context, expiresFrom);
                if (!Expiration.HasValue)
                {
                    options.Expires = expiresFrom.Add(_jiraOptions.RemoteAuthenticationTimeout);
                }
                return options;
            }
        }
    }
}