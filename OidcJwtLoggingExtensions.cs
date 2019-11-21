using Microsoft.Extensions.Logging;
using System;

namespace Hal24k.Auth.OidcJwtBearer
{
    /// <summary>
    /// Logging extensions taken from Microsoft.AspNetCore.Authentication.JwtBearer 
    /// </summary>
    internal static class OidcJwtLoggingExtensions
    {
        private static Action<ILogger, Exception> tokenValidationFailed =
            LoggerMessage.Define(
                eventId: 1,
                logLevel: LogLevel.Information,
                formatString: "Failed to validate the token.");

        private static Action<ILogger, Exception?> tokenValidationSucceeded =
            LoggerMessage.Define(
                eventId: 2,
                logLevel: LogLevel.Information,
                formatString: "Successfully validated the token.");

        private static Action<ILogger, Exception> errorProcessingMessage =
            LoggerMessage.Define(
                eventId: 3,
                logLevel: LogLevel.Error,
                formatString: "Exception occurred while processing message.");

        internal static void TokenValidationFailed(this ILogger logger, Exception ex)
            => tokenValidationFailed(logger, ex);

        internal static void TokenValidationSucceeded(this ILogger logger)
            => tokenValidationSucceeded(logger, null);

        internal static void ErrorProcessingMessage(this ILogger logger, Exception ex)
            => errorProcessingMessage(logger, ex);
    }
} 