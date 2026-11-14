using MaintenX.Api.Common.Errors;
using MaintenX.Api.Common.Health;
using MaintenX.Api.Common.Modules;
using MaintenX.Api.Common.Security;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// 1. Structured Logging and Configuration
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

// 2. Global Exception Handling via Problem Details (RFC 7807)
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

// 3. Security Infrastructure (JWT Key Ring, Trusted Proxies, Rate Limiting)
builder.Services.AddMaintenXSecurity(builder.Configuration, builder.Environment);

// 4. PostgreSQL Persistence (EF Core 10)
builder.Services.AddMaintenXPersistence(builder.Configuration);

// 5. Health Checks
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("postgresql", tags: new[] { "ready", "db" });

// 6. OpenAPI / Swagger Documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "MaintenX API",
        Version = "v1",
        Description = "Modular Monolith backend API for MaintenX Facility Maintenance SaaS platform. " +
                      "All business API routes follow /api/v{version}/[module]/[resource] conventions.",
        Contact = new OpenApiContact
        {
            Name = "MaintenX Engineering Team",
            Email = "engineering@maintenx.internal"
        }
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter JWT Bearer token containing valid signature, issuer, and 'kid' header."
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// 7. CORS policy for frontend clients (Web Next.js dev server & Mobile clients)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalClients", policy =>
    {
        policy.WithOrigins("http://localhost:3000", "http://127.0.0.1:3000")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
// 1. Process trusted reverse proxy forwarded headers before any other middleware
app.UseForwardedHeaders();

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "MaintenX API v1");
        c.RoutePrefix = "swagger";
    });
}

app.UseCors("AllowLocalClients");

// 2. Authoritative MaintenX Security Pipeline (Rate Limiting -> Authentication -> Authorization)
app.UseMaintenXSecurity();

// -----------------------------------------------------------------------------
// Health Check Endpoints (Anonymous & Excluded from Rate Limiting)
// -----------------------------------------------------------------------------

// Liveness probe: responds 200 Healthy if API process is alive and accepting traffic
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = _ => false, // Shallow check
    ResponseWriter = HealthCheckResponseWriter.WriteResponse
}).WithTags("Health").AllowAnonymous().DisableRateLimiting();

// Readiness probe: verifies downstream dependencies (PostgreSQL database connectivity)
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
    ResponseWriter = HealthCheckResponseWriter.WriteResponse
}).WithTags("Health").AllowAnonymous().DisableRateLimiting();

// -----------------------------------------------------------------------------
// Bootstrap Diagnostic & Versioning Route
// -----------------------------------------------------------------------------
app.MapGet("/api/v1/info", async (HttpContext context, IHostEnvironment env) =>
{
    var data = new
    {
        application = "MaintenX API",
        version = "1.0.0-bootstrap",
        environment = env.EnvironmentName,
        timestampUtc = DateTimeOffset.UtcNow,
        status = "Operational",
        apiVersioningConvention = "/api/v{version}/{module}/{resource}",
        plannedModules = new[]
        {
            "Tenancy",
            "Facilities",
            "Assets",
            "WorkOrders",
            "MaintenanceSchedules",
            "Notifications"
        }
    };
    context.Response.ContentType = "application/json; charset=utf-8";
    var options = new System.Text.Json.JsonSerializerOptions
    {
        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
    };
    await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(data, options));
}).WithName("GetApiInfo").WithTags("System").AllowAnonymous().DisableRateLimiting();

// -----------------------------------------------------------------------------
// Module Endpoint Discovery & Registration
// -----------------------------------------------------------------------------
foreach (var module in app.Services.GetServices<IModule>())
{
    module.MapEndpoints(app);
}

app.Logger.LogInformation("MaintenX API bootstrapping in {Environment} mode", app.Environment.EnvironmentName);

app.Run();

// Required for WebApplicationFactory in integration tests
public partial class Program { }
