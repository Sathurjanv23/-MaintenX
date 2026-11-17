namespace MaintenX.Api.Application.Auth;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using MaintenX.Api.Application.Auth.Contracts;
using MaintenX.Api.Application.Auth.Services;
using MaintenX.Api.Application.Auth.Validation;
using MaintenX.Api.Common.Modules;
using MaintenX.Api.Common.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

/// <summary>
/// Exposes authentication and session lifecycle endpoints conforming to FEAT-002 Minimal API specifications.
/// </summary>
public sealed class AuthModule : IModule
{
    /// <inheritdoc />
    public IServiceCollection RegisterModule(IServiceCollection services, IConfiguration configuration)
    {
        // Core auth dependencies and services are registered via AddMaintenXSecurity in SecurityServiceExtensions.
        return services;
    }

    /// <inheritdoc />
    public IEndpointRouteBuilder MapEndpoints(IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/v1/auth")
            .WithTags("Authentication");

        // 1. User Registration
        group.MapPost("/register", async (
            [FromBody] RegisterRequest? request,
            IAuthenticationService authService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (request is null)
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", "Request body cannot be empty.");
            }

            if (string.IsNullOrWhiteSpace(request.Email))
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", "Email address cannot be empty or whitespace.");
            }

            if (string.IsNullOrWhiteSpace(request.Password))
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", "Password cannot be empty or whitespace.");
            }

            if (request.Password.Length < PasswordValidation.MinPasswordLength || request.Password.Length > PasswordValidation.MaxPasswordLength)
            {
                return CreateProblem(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    "Bad Request",
                    $"Password length must be between {PasswordValidation.MinPasswordLength} and {PasswordValidation.MaxPasswordLength} characters.");
            }

            try
            {
                var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString();
                var result = await authService.RegisterAsync(request.Email, request.Password, ipAddress, cancellationToken);
                if (result.IsSuccess)
                {
                    return Results.Ok(new RegisterResponse(result.Message));
                }

                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", result.Message ?? "Registration failed.");
            }
            catch (ArgumentException ex)
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", ex.Message);
            }
        })
        .WithName("Register")
        .WithSummary("Register a new user account")
        .WithDescription("Creates a new user record or returns a generic success response to prevent account enumeration.")
        .AllowAnonymous()
        .RequireRateLimiting(AuthRateLimitPolicies.Registration)
        .Produces<RegisterResponse>(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .ProducesProblem(StatusCodes.Status429TooManyRequests);

        // 2. User Login
        group.MapPost("/login", async (
            [FromBody] LoginRequest? request,
            IAuthenticationService authService,
            TimeProvider timeProvider,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (request is null)
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", "Request body cannot be empty.");
            }

            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", "Email and password are required.");
            }

            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString();

            var result = await authService.LoginAsync(request.Email, request.Password, ipAddress, cancellationToken);

            if (result.IsSuccess && result.Tokens is not null)
            {
                var expiresInSeconds = (int)Math.Max(0, Math.Round((result.Tokens.AccessTokenExpiresAtUtc - timeProvider.GetUtcNow().UtcDateTime).TotalSeconds));
                var response = new LoginResponse(
                    result.Tokens.AccessToken,
                    result.Tokens.RefreshToken,
                    expiresInSeconds,
                    "Bearer",
                    result.Tokens.SessionId);

                return Results.Ok(response);
            }

            // Universal generic credential failure to mitigate user enumeration, lockout probing, and status disclosure
            return CreateProblem(
                httpContext,
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Invalid email or password.");
        })
        .WithName("Login")
        .WithSummary("Authenticate user and issue access and refresh tokens")
        .WithDescription("Authenticates user credentials and issues a JWT access token and single-use refresh token.")
        .AllowAnonymous()
        .RequireRateLimiting(AuthRateLimitPolicies.Login)
        .Produces<LoginResponse>(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .ProducesProblem(StatusCodes.Status401Unauthorized)
        .ProducesProblem(StatusCodes.Status429TooManyRequests);

        // 3. Refresh Token Rotation
        group.MapPost("/refresh", async (
            [FromBody] RefreshTokenRequest? request,
            IAuthenticationService authService,
            TimeProvider timeProvider,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (request is null || string.IsNullOrWhiteSpace(request.RefreshToken))
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", "Refresh token cannot be empty.");
            }

            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString();

            var result = await authService.RefreshTokenAsync(request.RefreshToken, ipAddress, cancellationToken);

            if (result.IsSuccess && result.Tokens is not null)
            {
                var expiresInSeconds = (int)Math.Max(0, Math.Round((result.Tokens.AccessTokenExpiresAtUtc - timeProvider.GetUtcNow().UtcDateTime).TotalSeconds));
                var response = new RefreshTokenResponse(
                    result.Tokens.AccessToken,
                    result.Tokens.RefreshToken,
                    expiresInSeconds,
                    "Bearer",
                    result.Tokens.SessionId);

                return Results.Ok(response);
            }

            // Generic error for invalid, expired, revoked, or replayed tokens without leaking session topology
            return CreateProblem(
                httpContext,
                StatusCodes.Status401Unauthorized,
                "Unauthorized",
                "Invalid or expired refresh token.");
        })
        .WithName("RefreshToken")
        .WithSummary("Rotate refresh token and issue new token pair")
        .WithDescription("Accepts an active single-use refresh token in request body, revokes it, and issues a rotated pair.")
        .AllowAnonymous()
        .RequireRateLimiting(AuthRateLimitPolicies.Refresh)
        .Produces<RefreshTokenResponse>(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .ProducesProblem(StatusCodes.Status401Unauthorized)
        .ProducesProblem(StatusCodes.Status429TooManyRequests);

        // 4. Logout
        group.MapPost("/logout", async (
            IAuthenticationService authService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (!TryGetAuthenticatedUserId(httpContext.User, out var userId))
            {
                return CreateProblem(httpContext, StatusCodes.Status401Unauthorized, "Unauthorized", "Invalid or missing user identity claim.");
            }

            if (!TryGetAuthenticatedSessionId(httpContext.User, out var sessionId))
            {
                return CreateProblem(httpContext, StatusCodes.Status401Unauthorized, "Unauthorized", "Invalid or missing session identity claim.");
            }

            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString();
            var result = await authService.LogoutAsync(sessionId, userId, ipAddress, cancellationToken);

            if (result.IsSuccess)
            {
                return Results.NoContent();
            }

            return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", result.Message ?? "Logout failed.");
        })
        .WithName("Logout")
        .WithSummary("Revoke active user session and associated refresh tokens")
        .WithDescription("Terminates the caller's active session and bulk-revokes its associated refresh tokens using claims identity.")
        .RequireAuthorization()
        .Produces(StatusCodes.Status204NoContent)
        .ProducesProblem(StatusCodes.Status401Unauthorized);

        // 5. Change Password
        group.MapPost("/change-password", async (
            [FromBody] ChangePasswordRequest? request,
            IAuthenticationService authService,
            HttpContext httpContext,
            CancellationToken cancellationToken) =>
        {
            if (request is null)
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", "Request body cannot be empty.");
            }

            if (string.IsNullOrWhiteSpace(request.CurrentPassword))
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", "Current password cannot be empty or whitespace.");
            }

            if (string.IsNullOrWhiteSpace(request.NewPassword))
            {
                return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", "New password cannot be empty or whitespace.");
            }

            if (request.NewPassword.Length < PasswordValidation.MinPasswordLength || request.NewPassword.Length > PasswordValidation.MaxPasswordLength)
            {
                return CreateProblem(
                    httpContext,
                    StatusCodes.Status400BadRequest,
                    "Bad Request",
                    $"New password length must be between {PasswordValidation.MinPasswordLength} and {PasswordValidation.MaxPasswordLength} characters.");
            }

            if (!TryGetAuthenticatedUserId(httpContext.User, out var userId))
            {
                return CreateProblem(httpContext, StatusCodes.Status401Unauthorized, "Unauthorized", "Invalid or missing user identity claim.");
            }

            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString();
            var result = await authService.ChangePasswordAsync(userId, request.CurrentPassword, request.NewPassword, ipAddress, cancellationToken);

            if (result.IsSuccess)
            {
                return Results.Ok(PasswordMutationResponse.Success());
            }

            return CreateProblem(httpContext, StatusCodes.Status400BadRequest, "Bad Request", result.ErrorMessage ?? "Password change failed.");
        })
        .WithName("ChangePassword")
        .WithSummary("Update password and revoke all active sessions")
        .WithDescription("Verifies current credentials, updates password hash, rotates security stamp, and revokes all active sessions.")
        .RequireAuthorization()
        .Produces<PasswordMutationResponse>(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .ProducesProblem(StatusCodes.Status401Unauthorized);

        return endpoints;
    }

    private static IResult CreateProblem(
        HttpContext httpContext,
        int statusCode,
        string title,
        string detail)
    {
        var problemDetails = new ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Detail = detail,
            Instance = httpContext.Request.Path,
            Extensions =
            {
                ["traceId"] = httpContext.TraceIdentifier,
                ["timestamp"] = DateTimeOffset.UtcNow
            }
        };

        return Results.Problem(problemDetails);
    }

    private static bool TryGetAuthenticatedUserId(ClaimsPrincipal user, out Guid userId)
    {
        userId = Guid.Empty;
        var sub = user.FindFirstValue(ClaimTypes.NameIdentifier)
                  ?? user.FindFirstValue(JwtRegisteredClaimNames.Sub)
                  ?? user.FindFirstValue("sub");

        return Guid.TryParse(sub, out userId) && userId != Guid.Empty;
    }

    private static bool TryGetAuthenticatedSessionId(ClaimsPrincipal user, out Guid sessionId)
    {
        sessionId = Guid.Empty;
        var sid = user.FindFirstValue("sid");

        return Guid.TryParse(sid, out sessionId) && sessionId != Guid.Empty;
    }
}
