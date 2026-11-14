namespace MaintenX.UnitTests.Security;

/// <summary>
/// Deterministic TimeProvider implementation for unit and integration testing.
/// </summary>
public sealed class TestTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow;

    public TestTimeProvider(DateTimeOffset initialUtcNow)
    {
        _utcNow = initialUtcNow;
    }

    public override DateTimeOffset GetUtcNow() => _utcNow;

    public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);

    public void SetUtcNow(DateTimeOffset newUtcNow) => _utcNow = newUtcNow;
}

