# OidcJwtBearer

Provides an extension to the JwtBearer middleware for ASP.NET Core. In addition to verifying an access token, it will also fetch the userinfo from the identity/oidc provider, and populate the UserPrincipal with that data.

To use this you need:
* An openid provider
* The access token needs the openid scope and the scopes for any other information you want to request

## Example

```cs
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        // ...

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddOidcJwtBearer(options =>
                {
                    // Base-address of your identityserver
                    options.Authority = "https://demo.identityserver.io";

                    // Name of the API resource
                    options.Audience = "my_api";
                    
                    // Save the access token for use later
                    options.SaveToken = true;
                    
                    // Map a custom claim to your user-principal
                    options.ClaimActions.MapJsonKey("custom_claim", "custom_claim");
                });
                
        // ...
    }

    public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
    {
        // ...
        
        app.UseAuthentication();
        
        // ...
    }
}
```
