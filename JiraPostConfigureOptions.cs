using AspNet.Security.OAuth.Jira.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Jira
{
    public class JiraPostConfigureOptions : IPostConfigureOptions<JiraOptions>
    {
        private readonly IDataProtectionProvider _dataProtection;
        
        public JiraPostConfigureOptions(IDataProtectionProvider dataProtection)
        {
            _dataProtection = dataProtection;
        }

        public void PostConfigure(string name, JiraOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dataProtection;

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(JiraAuthenticationHandler).FullName, name, "v1");
                options.StateDataFormat = new SecureDataFormat<RequestToken>(new RequestTokenSerializer(), dataProtector);
            }
        }
    }
}