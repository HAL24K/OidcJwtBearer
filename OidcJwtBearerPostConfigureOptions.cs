using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Hal24k.Auth.OidcJwtBearer
{
    /// <summary>
    /// Does post-processing for OidcJwtBearerOptions, fills in missing values and does some validation
    /// </summary>
    internal class OidcJwtBearerPostConfigureOptions : IPostConfigureOptions<OidcJwtBearerOptions>
    {
        public void PostConfigure(string name, OidcJwtBearerOptions options)
            => new JwtBearerPostConfigureOptions().PostConfigure(name, options);
    }
}