# OidcJwtBearer

Provides an extension to the JwtBearer middleware for ASP.NET Core. In addition to verifying an access token, it will also fetch the userinfo from the identity/oidc provider, and populate the UserPrincipal with that data.

To use this you need:
* An openid provider
* The access token needs the openid scope and the scopes for any other information you want to request

## Example

`

`