using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

namespace Hal24k.Auth.OidcJwtBearer
{
    /// <summary>
    /// Extensions that aid in adding the OidcJwtBearer middleware to an application
    /// </summary>
    public static class OidcJwtBearerExtensions
    {
        /// <summary>
        /// Add the OidcJwtBearer middleware with the default authentication schema
        /// </summary>
        /// <param name="builder">The current AuthenticationBuilder</param>
        /// <returns>The AuthenticationBuilder with the OidcJwtBearer middleware added</returns>
        public static AuthenticationBuilder AddOidcJwtBearer(this AuthenticationBuilder builder)
            => builder.AddOidcJwtBearer(JwtBearerDefaults.AuthenticationScheme, _ => { });

        /// <summary>
        /// Add the OidcJwtBearer middleware with the default authentication schema
        /// </summary>
        /// <param name="builder">The current AuthenticationBuilder</param>
        /// <param name="configureOptions">A callback to configure options</param>
        /// <returns>The AuthenticationBuilder with the OidcJwtBearer middleware added</returns>
        public static AuthenticationBuilder AddOidcJwtBearer(this AuthenticationBuilder builder, Action<OidcJwtBearerOptions> configureOptions)
            => builder.AddOidcJwtBearer(JwtBearerDefaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Add the OidcJwtBearer middleware
        /// </summary>
        /// <param name="builder">The current AuthenticationBuilder</param>
        /// <param name="configureOptions">A callback to configure options</param>
        /// <param name="authenticationScheme">The authentication schema</param>
        /// <returns>The AuthenticationBuilder with the OidcJwtBearer middleware added</returns>
        public static AuthenticationBuilder AddOidcJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, Action<OidcJwtBearerOptions> configureOptions)
            => builder.AddOidcJwtBearer(authenticationScheme, displayName: null, configureOptions: configureOptions);


        /// <summary>
        /// Add the OidcJwtBearer middleware
        /// </summary>
        /// <param name="builder">The current AuthenticationBuilder</param>
        /// <param name="configureOptions">A callback to configure options</param>
        /// <param name="authenticationScheme">The authentication schema</param>
        /// <param name="displayName">The display name</param>
        /// <returns>The AuthenticationBuilder with the OidcJwtBearer middleware added</returns>
        public static AuthenticationBuilder AddOidcJwtBearer(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<OidcJwtBearerOptions> configureOptions)
        {
            builder.Services.AddMemoryCache();
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OidcJwtBearerOptions>, OidcJwtBearerPostConfigureOptions>());
            return builder.AddScheme<OidcJwtBearerOptions, OidcJwtBearerHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
