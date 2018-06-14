using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Jira
{
    public static class JiraExtensions
    {
        public static AuthenticationBuilder AddJira(this AuthenticationBuilder builder)
            => builder.AddJira(JiraDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddJira(this AuthenticationBuilder builder, Action<JiraOptions> configureOptions)
            => builder.AddJira(JiraDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddJira(this AuthenticationBuilder builder, string authenticationScheme, Action<JiraOptions> configureOptions)
            => builder.AddJira(authenticationScheme, JiraDefaults.DisplayName, configureOptions);

        public static AuthenticationBuilder AddJira(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<JiraOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JiraOptions>, JiraPostConfigureOptions>());
            return builder.AddRemoteScheme<JiraOptions, JiraAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}