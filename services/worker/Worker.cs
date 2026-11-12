namespace MaintenX.Worker;

public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("MaintenX Background Worker service initialized. Awaiting scheduled tasks and jobs...");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Heartbeat check for worker subsystem
                _logger.LogDebug("MaintenX Background Worker heartbeat pulse at: {Time}", DateTimeOffset.UtcNow);
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                _logger.LogInformation("MaintenX Background Worker cancellation requested. Shutting down gracefully.");
                break;
            }
        }
    }
}
