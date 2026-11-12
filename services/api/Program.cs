using MaintenX.Api.Common.Errors;
using MaintenX.Api.Common.Health;
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

// 3. Health Checks
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("postgresql", tags: new[] { "ready", "db" });

// 4. OpenAPI / Swagger Documentation
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
});

// 5. CORS policy for frontend clients (Web Next.js dev server & Mobile clients)
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

// -----------------------------------------------------------------------------
// Health Check Endpoints
// -----------------------------------------------------------------------------

// Liveness probe: responds 200 Healthy if API process is alive and accepting traffic
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = _ => false, // Shallow check
    ResponseWriter = HealthCheckResponseWriter.WriteResponse
}).WithTags("Health").AllowAnonymous();

// Readiness probe: verifies downstream dependencies (PostgreSQL database connectivity)
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains("ready"),
    ResponseWriter = HealthCheckResponseWriter.WriteResponse
}).WithTags("Health").AllowAnonymous();

// -----------------------------------------------------------------------------
// Bootstrap Diagnostic & Versioning Route
// -----------------------------------------------------------------------------
app.MapGet("/api/v1/info", (IHostEnvironment env) => Results.Ok(new
{
    Application = "MaintenX API",
    Version = "1.0.0-bootstrap",
    Environment = env.EnvironmentName,
    TimestampUtc = DateTimeOffset.UtcNow,
    Status = "Operational",
    ApiVersioningConvention = "/api/v{version}/{module}/{resource}",
    PlannedModules = new[]
    {
        "Tenancy",
        "Facilities",
        "Assets",
        "WorkOrders",
        "MaintenanceSchedules",
        "Notifications"
    }
})).WithName("GetApiInfo").WithTags("System").AllowAnonymous();

app.Logger.LogInformation("MaintenX API bootstrapping in {Environment} mode", app.Environment.EnvironmentName);

app.Run();

// Required for WebApplicationFactory in integration tests
public partial class Program { }
