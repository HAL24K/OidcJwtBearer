using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System.Diagnostics.CodeAnalysis;

namespace Hal24k.Auth.OidcJwtBearer
{
    /// <summary>
    /// This is the OidcJwtBearer authentication middleware. 
    /// <rant>
    /// Unfortunately the original JwtBearerHandler is not extendable due to how the AuthenticationHandler is structured. There is an IAuthenticationHandler 
    /// interface, but AuthenticationBuilder.AddScheme only takes the AuthenticationHandler abstract class as parameter. Why even have that interface
    /// if you can't use it. It results in a non-extendable class, so this class contains copy-pasted code from the Microsoft.AspNetCore.Authentication.JwtBearer 
    /// package.
    /// </rant>
    /// </summary>
    internal class OidcJwtBearerHandler : AuthenticationHandler<OidcJwtBearerOptions>
    {
        private readonly IMemoryCache cache;
        private OpenIdConnectConfiguration? configuration;

        public OidcJwtBearerHandler(IMemoryCache cache, IOptionsMonitor<OidcJwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
            this.cache = cache;
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring. 
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new JwtBearerEvents Events
        {
            get => (JwtBearerEvents)base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// Initialize a new event object
        /// </summary>
        /// <returns>The initialized JwtBearerEvents</returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new JwtBearerEvents());

        /// <summary>
        /// Searches the 'Authorization' header for a 'Bearer' token. If the 'Bearer' token is found, it is validated using <see cref="TokenValidationParameters"/> set in the options.
        /// </summary>
        /// <returns>The authentication result</returns>
        protected override async Task<AuthenticateResult?> HandleAuthenticateAsync()
        {
            string? token = null;
            try
            {
                // Give application opportunity to find from a different location, adjust, or reject token
                var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);

                // event can set the token
                await Events.MessageReceived(messageReceivedContext).ConfigureAwait(false);
                if (messageReceivedContext.Result != null)
                {
                    return messageReceivedContext.Result;
                }

                // If application retrieved token from somewhere else, use that.
                token = messageReceivedContext.Token;

                if (string.IsNullOrEmpty(token))
                {
                    string authorization = Request.Headers["Authorization"];

                    // If no authorization header found, nothing to process further
                    if (string.IsNullOrEmpty(authorization))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        token = authorization.Substring("Bearer ".Length).Trim();
                    }

                    // If no token found, no further work possible
                    if (string.IsNullOrEmpty(token))
                    {
                        return AuthenticateResult.NoResult();
                    }
                }

                if (configuration == null && Options.ConfigurationManager != null)
                {
                    configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted).ConfigureAwait(false);
                }

                var validationParameters = Options.TokenValidationParameters.Clone();
                if (configuration != null)
                {
                    var issuers = new[] { configuration.Issuer };
                    validationParameters.ValidIssuers = validationParameters.ValidIssuers?.Concat(issuers) ?? issuers;

                    validationParameters.IssuerSigningKeys = validationParameters.IssuerSigningKeys?.Concat(configuration.SigningKeys)
                        ?? configuration.SigningKeys;
                }

                List<Exception>? validationFailures = null;
                SecurityToken validatedToken;
                foreach (var validator in Options.SecurityTokenValidators)
                {
                    if (validator.CanReadToken(token))
                    {
                        ClaimsPrincipal principal;
                        try
                        {
                            principal = validator.ValidateToken(token, validationParameters, out validatedToken);
                        }
#pragma warning disable CA1031 // Do not catch general exception types
                        catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
                        {
                            Logger.TokenValidationFailed(ex);

                            // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the event.
                            if (Options.RefreshOnIssuerKeyNotFound && Options.ConfigurationManager != null
                                && ex is SecurityTokenSignatureKeyNotFoundException)
                            {
                                Options.ConfigurationManager.RequestRefresh();
                            }

                            if (validationFailures == null)
                            {
                                validationFailures = new List<Exception>(1);
                            }

                            validationFailures.Add(ex);
                            continue;
                        }

                        Logger.TokenValidationSucceeded();

                        var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
                        {
                            Principal = principal,
                            SecurityToken = validatedToken
                        };

                        await AddUserInfoToPrincipal(tokenValidatedContext).ConfigureAwait(false);
                        await Events.TokenValidated(tokenValidatedContext).ConfigureAwait(false);
                        if (tokenValidatedContext.Result != null)
                        {
                            return tokenValidatedContext.Result;
                        }

                        if (Options.SaveToken)
                        {
                            tokenValidatedContext.Properties.StoreTokens(new[]
                            {
                                new AuthenticationToken { Name = "access_token", Value = token }
                            });
                        }

                        tokenValidatedContext.Success();
                        return tokenValidatedContext.Result;
                    }
                }

                if (validationFailures != null)
                {
                    var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                    {
                        Exception = (validationFailures.Count == 1) ? validationFailures[0] : new AggregateException(validationFailures)
                    };

                    await Events.AuthenticationFailed(authenticationFailedContext).ConfigureAwait(false);
                    if (authenticationFailedContext.Result != null)
                    {
                        return authenticationFailedContext.Result;
                    }

                    return AuthenticateResult.Fail(authenticationFailedContext.Exception);
                }

                return AuthenticateResult.Fail("No SecurityTokenValidator available for token: " + token ?? "[null]");
            }
            catch (Exception ex)
            {
                Logger.ErrorProcessingMessage(ex);

                var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex
                };

                await Events.AuthenticationFailed(authenticationFailedContext).ConfigureAwait(false);
                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                throw;
            }
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var authResult = await HandleAuthenticateOnceSafeAsync().ConfigureAwait(false);
            var eventContext = new JwtBearerChallengeContext(Context, Scheme, Options, properties)
            {
                AuthenticateFailure = authResult?.Failure
            };

            // Avoid returning error=invalid_token if the error is not caused by an authentication failure (e.g missing token).
            if (Options.IncludeErrorDetails && eventContext.AuthenticateFailure != null)
            {
                eventContext.Error = "invalid_token";
                eventContext.ErrorDescription = CreateErrorDescription(eventContext.AuthenticateFailure);
            }

            await Events.Challenge(eventContext).ConfigureAwait(false);
            if (eventContext.Handled)
            {
                return;
            }

            Response.StatusCode = 401;

            if (string.IsNullOrEmpty(eventContext.Error) &&
                string.IsNullOrEmpty(eventContext.ErrorDescription) &&
                string.IsNullOrEmpty(eventContext.ErrorUri))
            {
                Response.Headers.Append(HeaderNames.WWWAuthenticate, Options.Challenge);
            }
            else
            {
                // https://tools.ietf.org/html/rfc6750#section-3.1
                // WWW-Authenticate: Bearer realm="example", error="invalid_token", error_description="The access token expired"
                var builder = new StringBuilder(Options.Challenge);
                if (Options.Challenge.IndexOf(" ", StringComparison.Ordinal) > 0)
                {
                    // Only add a comma after the first param, if any
                    builder.Append(',');
                }

                if (!string.IsNullOrEmpty(eventContext.Error))
                {
                    builder.Append(" error=\"");
                    builder.Append(eventContext.Error);
                    builder.Append("\"");
                }

                if (!string.IsNullOrEmpty(eventContext.ErrorDescription))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_description=\"");
                    builder.Append(eventContext.ErrorDescription);
                    builder.Append('\"');
                }

                if (!string.IsNullOrEmpty(eventContext.ErrorUri))
                {
                    if (!string.IsNullOrEmpty(eventContext.Error) ||
                        !string.IsNullOrEmpty(eventContext.ErrorDescription))
                    {
                        builder.Append(",");
                    }

                    builder.Append(" error_uri=\"");
                    builder.Append(eventContext.ErrorUri);
                    builder.Append('\"');
                }

                Response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());
            }
        }

        private static string CreateErrorDescription(Exception authFailure)
        {
            IEnumerable<Exception> exceptions;
            if (authFailure is AggregateException agEx)
            {
                exceptions = agEx.InnerExceptions;
            }
            else
            {
                exceptions = new[] { authFailure };
            }

            var messages = new List<string>();

            foreach (var ex in exceptions)
            {
                // Order sensitive, some of these exceptions derive from others
                // and we want to display the most specific message possible.
                switch (ex)
                {
                    case SecurityTokenInvalidAudienceException _:
                        messages.Add("The audience is invalid");
                        break;
                    case SecurityTokenInvalidIssuerException _:
                        messages.Add("The issuer is invalid");
                        break;
                    case SecurityTokenNoExpirationException _:
                        messages.Add("The token has no expiration");
                        break;
                    case SecurityTokenInvalidLifetimeException _:
                        messages.Add("The token lifetime is invalid");
                        break;
                    case SecurityTokenNotYetValidException _:
                        messages.Add("The token is not valid yet");
                        break;
                    case SecurityTokenExpiredException _:
                        messages.Add("The token is expired");
                        break;
                    case SecurityTokenSignatureKeyNotFoundException _:
                        messages.Add("The signature key was not found");
                        break;
                    case SecurityTokenInvalidSignatureException _:
                        messages.Add("The signature is invalid");
                        break;
                }
            }

            return string.Join("; ", messages);
        }

        private async Task AddUserInfoToPrincipal(TokenValidatedContext context)
        {
            var token = (JwtSecurityToken)context.SecurityToken;
            using (var userInfo = await GetUserInfo(token).ConfigureAwait(false))
            {
                ClaimsIdentity identity = GetIdentity(userInfo, token);
                context.Principal.AddIdentity(identity);
            }
        }

        private async Task<JsonDocument> GetUserInfo(JwtSecurityToken token)
        {
            string userInfo;
            OidcCacheKey cacheKey = new OidcCacheKey(token.RawData);
            if (!cache.TryGetValue(cacheKey, out userInfo))
            {
                userInfo = await FetchUserInfo(token).ConfigureAwait(false);
                cache.Set(cacheKey, userInfo, new MemoryCacheEntryOptions() { AbsoluteExpiration = token.ValidTo.AddSeconds(-5), Size = userInfo.Length });
            }

            return JsonDocument.Parse(userInfo);
        }

        private async Task<string> FetchUserInfo(JwtSecurityToken token)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.RawData);
                Uri userinfoEndpoint = new Uri(configuration?.UserInfoEndpoint ?? throw new HttpRequestException("No known token-endpoint"));
                using (HttpResponseMessage userInfoResponse = await client.GetAsync(userinfoEndpoint).ConfigureAwait(false))
                {
                    userInfoResponse.EnsureSuccessStatusCode();
                    string responseBody = await userInfoResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                    return responseBody;
                }
            }
        }

        private ClaimsIdentity GetIdentity(JsonDocument userInfo, JwtSecurityToken token)
        {
            var identity = new ClaimsIdentity();
            foreach (var action in Options.ClaimActions)
            {
                action.Run(userInfo.RootElement, identity, token.Issuer);
            }

            return identity;
        }

        private class OidcCacheKey : IEquatable<OidcCacheKey>
        {
            public OidcCacheKey(string key)
            {
                Key = key;
            }

            public string Key { get; }

            public bool Equals([AllowNull] OidcCacheKey? other)
                => other != null &&
                   Key == other.Key;

            public override bool Equals(object? other)
                => Equals(other as OidcCacheKey);

            public override int GetHashCode()
                => Key.GetHashCode(StringComparison.Ordinal);
        }
    }
}