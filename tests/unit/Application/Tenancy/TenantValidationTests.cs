namespace MaintenX.UnitTests.Application.Tenancy;

using MaintenX.Api.Application.Tenancy.Validation;
using Xunit;

/// <summary>
/// Unit tests for TenantValidation enforcing length boundaries, slug patterns,
/// GUID validity, and administrative reasons.
/// </summary>
public class TenantValidationTests
{
    // =========================================================================
    // 1. SLUG VALIDATION TESTS
    // =========================================================================

    [Theory]
    [InlineData("acme", "acme")]
    [InlineData("Acme", "acme")]
    [InlineData("ACME-CORP", "acme-corp")]
    [InlineData("acme-corp", "acme-corp")]
    [InlineData("facility-101", "facility-101")]
    [InlineData("a1", "a1")]
    [InlineData("tenant-with-multiple-hyphen-separated-words", "tenant-with-multiple-hyphen-separated-words")]
    public void ValidateAndNormalizeSlug_ValidSlugs_ReturnsNormalizedSlug(string input, string expected)
    {
        var result = TenantValidation.ValidateAndNormalizeSlug(input);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ValidateAndNormalizeSlug_ExactlyMinLength_ReturnsNormalizedSlug()
    {
        var result = TenantValidation.ValidateAndNormalizeSlug("ab");
        Assert.Equal("ab", result);
    }

    [Fact]
    public void ValidateAndNormalizeSlug_ExactlyMaxLength_ReturnsNormalizedSlug()
    {
        var slug = new string('a', 100);
        var result = TenantValidation.ValidateAndNormalizeSlug(slug);
        Assert.Equal(slug, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("   \t   ")]
    public void ValidateAndNormalizeSlug_NullOrWhitespace_ThrowsArgumentException(string? invalidSlug)
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndNormalizeSlug(invalidSlug));
        Assert.Equal("slug", ex.ParamName);
    }

    [Theory]
    [InlineData(" acme")]
    [InlineData("acme ")]
    [InlineData(" acme ")]
    public void ValidateAndNormalizeSlug_LeadingOrTrailingWhitespace_ThrowsArgumentException(string invalidSlug)
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndNormalizeSlug(invalidSlug));
        Assert.Contains("whitespace", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("a")] // 1 char, min is 2
    public void ValidateAndNormalizeSlug_ShorterThanMinLength_ThrowsArgumentException(string shortSlug)
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndNormalizeSlug(shortSlug));
        Assert.Contains("between 2 and 100", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateAndNormalizeSlug_LongerThanMaxLength_ThrowsArgumentException()
    {
        var longSlug = new string('a', 101);
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndNormalizeSlug(longSlug));
        Assert.Contains("between 2 and 100", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("acme--corp")] // Consecutive hyphens
    [InlineData("-acme")] // Leading hyphen
    [InlineData("acme-")] // Trailing hyphen
    [InlineData("acme_corp")] // Underscore
    [InlineData("acme.corp")] // Period
    [InlineData("acme@corp")] // Special symbol
    [InlineData("acme corp")] // Space within
    public void ValidateAndNormalizeSlug_InvalidPattern_ThrowsArgumentException(string invalidSlug)
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndNormalizeSlug(invalidSlug));
        Assert.Contains("invalid", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // 2. DISPLAY NAME VALIDATION TESTS
    // =========================================================================

    [Theory]
    [InlineData("Acme Corporation", "Acme Corporation")]
    [InlineData("  Acme Facilities  ", "Acme Facilities")]
    [InlineData("AB", "AB")]
    public void ValidateAndTrimDisplayName_ValidName_ReturnsTrimmed(string input, string expected)
    {
        var result = TenantValidation.ValidateAndTrimDisplayName(input);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ValidateAndTrimDisplayName_ExactlyMaxLength_ReturnsTrimmed()
    {
        var name = new string('A', 100);
        var result = TenantValidation.ValidateAndTrimDisplayName(name);
        Assert.Equal(name, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("   \t   ")]
    public void ValidateAndTrimDisplayName_NullOrWhitespace_ThrowsArgumentException(string? invalidName)
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndTrimDisplayName(invalidName));
        Assert.Equal("displayName", ex.ParamName);
    }

    [Theory]
    [InlineData("A")]
    [InlineData(" A ")]
    public void ValidateAndTrimDisplayName_TooShort_ThrowsArgumentException(string shortName)
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndTrimDisplayName(shortName));
        Assert.Contains("between 2 and 100", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateAndTrimDisplayName_TooLong_ThrowsArgumentException()
    {
        var longName = new string('X', 101);
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateAndTrimDisplayName(longName));
        Assert.Contains("between 2 and 100", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // 3. IDENTIFIER VALIDATION TESTS
    // =========================================================================

    [Fact]
    public void ValidateTenantId_ValidGuid_DoesNotThrow()
    {
        var validId = Guid.NewGuid();
        TenantValidation.ValidateTenantId(validId); // Should not throw
    }

    [Fact]
    public void ValidateTenantId_EmptyGuid_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateTenantId(Guid.Empty));
        Assert.Equal("tenantId", ex.ParamName);
    }

    [Fact]
    public void ValidateUserId_ValidGuid_DoesNotThrow()
    {
        var validId = Guid.NewGuid();
        TenantValidation.ValidateUserId(validId); // Should not throw
    }

    [Fact]
    public void ValidateUserId_EmptyGuid_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateUserId(Guid.Empty));
        Assert.Equal("userId", ex.ParamName);
    }

    // =========================================================================
    // 4. REASON VALIDATION TESTS
    // =========================================================================

    [Theory]
    [InlineData("Security investigation", "Security investigation")]
    [InlineData("  Billing delinquency  ", "Billing delinquency")]
    [InlineData("ABC", "ABC")] // Exactly min length 3
    public void ValidateReason_ValidReason_ReturnsTrimmed(string input, string expected)
    {
        var result = TenantValidation.ValidateReason(input);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ValidateReason_ExactlyMaxLength_ReturnsTrimmed()
    {
        var reason = new string('R', 500);
        var result = TenantValidation.ValidateReason(reason);
        Assert.Equal(reason, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("   \t   ")]
    public void ValidateReason_NullOrWhitespace_ThrowsArgumentException(string? invalidReason)
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateReason(invalidReason));
        Assert.Equal("reason", ex.ParamName);
    }

    [Theory]
    [InlineData("A")]
    [InlineData("AB")]
    [InlineData(" AB ")]
    public void ValidateReason_TooShort_ThrowsArgumentException(string shortReason)
    {
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateReason(shortReason));
        Assert.Contains("between 3 and 500", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateReason_TooLong_ThrowsArgumentException()
    {
        var longReason = new string('Z', 501);
        var ex = Assert.Throws<ArgumentException>(() => TenantValidation.ValidateReason(longReason));
        Assert.Contains("between 3 and 500", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
