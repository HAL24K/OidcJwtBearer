using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;

namespace Hal24k.Auth.OidcJwtBearer
{
    /// <summary>
    /// Options class provides configuration for the OidcJwtBearer middleware.
    /// </summary>
    public class OidcJwtBearerOptions : JwtBearerOptions
    {
        private static string[] deletedClaims = new string[]
        {
            "nonce",
            "aud",
            "azp",
            "acr",
            "amr",
            "iss",
            "iat",
            "nbf",
            "exp",
            "at_hash",
            "c_hash",
            "auth_time",
            "ipaddr",
            "platf",
            "ver"
        };

        private static string[] mappedClaims = new string[]
        {
            "sub",
            "name",
            "given_name",
            "family_name",
            "profile",
            "email",
        };

        /// <summary>
        /// Initialize OidcJwtBearerOptions
        /// </summary>
        public OidcJwtBearerOptions()
        {
            ClaimActions = new ClaimActionCollection();

            foreach (string deleted in deletedClaims)
            {
                ClaimActions.DeleteClaim(deleted);
            }

            // Map query claims
            foreach (string mapped in mappedClaims)
            {
                ClaimActions.MapJsonKey(mapped, mapped);
            }
        }

        /// <summary>
        /// Configure how claims will be 
        /// </summary>
        public ClaimActionCollection ClaimActions { get; set; }
    }
} 