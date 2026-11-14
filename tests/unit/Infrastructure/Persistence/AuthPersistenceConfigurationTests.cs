namespace MaintenX.UnitTests.Infrastructure.Persistence;

using System.Reflection;
using System.Text.Json;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using MaintenX.Api.Infrastructure.Persistence.Configurations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Xunit;

public class AuthPersistenceConfigurationTests
{
    private static IModel CreateModel()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql("Host=localhost;Database=dummy;Username=dummy;Password=dummy")
            .Options;

        using var context = new MaintenXDbContext(options);
        return context.GetService<IDesignTimeModel>().Model;
    }

    [Fact]
    public void Model_ContainsAllAuthEntitiesInPlatformSchema()
    {
        var model = CreateModel();

        var userEntity = model.FindEntityType(typeof(User));
        Assert.NotNull(userEntity);
        Assert.Equal("users", userEntity.GetTableName());
        Assert.Equal("platform", userEntity.GetSchema());

        var sessionEntity = model.FindEntityType(typeof(UserSession));
        Assert.NotNull(sessionEntity);
        Assert.Equal("user_sessions", sessionEntity.GetTableName());
        Assert.Equal("platform", sessionEntity.GetSchema());

        var tokenEntity = model.FindEntityType(typeof(RefreshToken));
        Assert.NotNull(tokenEntity);
        Assert.Equal("refresh_tokens", tokenEntity.GetTableName());
        Assert.Equal("platform", tokenEntity.GetSchema());

        var auditEntity = model.FindEntityType(typeof(SecurityAuditEvent));
        Assert.NotNull(auditEntity);
        Assert.Equal("security_audit_events", auditEntity.GetTableName());
        Assert.Equal("platform", auditEntity.GetSchema());
    }

    [Fact]
    public void UserConfiguration_ConfiguresColumnsConstraintsAndIndexesCorrectly()
    {
        var model = CreateModel();
        var entity = model.FindEntityType(typeof(User))!;

        // Primary Key
        var pk = entity.FindPrimaryKey();
        Assert.NotNull(pk);
        Assert.Equal("pk_users", pk.GetName());
        Assert.Single(pk.Properties);
        Assert.Equal("Id", pk.Properties[0].Name);

        // Email
        var emailProp = entity.FindProperty(nameof(User.Email))!;
        Assert.False(emailProp.IsNullable);
        Assert.Equal("email", emailProp.GetColumnName());
        Assert.Equal(256, emailProp.GetMaxLength());

        var emailIndex = entity.GetIndexes().FirstOrDefault(i => i.Properties.Any(p => p.Name == nameof(User.Email)));
        Assert.NotNull(emailIndex);
        Assert.True(emailIndex.IsUnique);
        Assert.Equal("ix_users_email", emailIndex.GetDatabaseName());

        // PasswordHash & SecurityStamp
        var pwdProp = entity.FindProperty(nameof(User.PasswordHash))!;
        Assert.False(pwdProp.IsNullable);
        Assert.Equal("password_hash", pwdProp.GetColumnName());
        Assert.Equal(500, pwdProp.GetMaxLength());

        var stampProp = entity.FindProperty(nameof(User.SecurityStamp))!;
        Assert.False(stampProp.IsNullable);
        Assert.Equal("security_stamp", stampProp.GetColumnName());
        Assert.Equal(64, stampProp.GetMaxLength());

        // Status
        var statusProp = entity.FindProperty(nameof(User.Status))!;
        Assert.False(statusProp.IsNullable);
        Assert.Equal("status", statusProp.GetColumnName());
        Assert.Equal(50, statusProp.GetMaxLength());

        // FailedLoginAttempts
        var failedProp = entity.FindProperty(nameof(User.FailedLoginAttempts))!;
        Assert.False(failedProp.IsNullable);
        Assert.Equal("failed_login_attempts", failedProp.GetColumnName());
        Assert.Equal(0, failedProp.GetDefaultValue());

        // Timestamps
        var createdProp = entity.FindProperty(nameof(User.CreatedAtUtc))!;
        Assert.False(createdProp.IsNullable);
        Assert.Equal("created_at_utc", createdProp.GetColumnName());
        Assert.Equal("timestamp with time zone", createdProp.GetColumnType());

        var updatedProp = entity.FindProperty(nameof(User.UpdatedAtUtc))!;
        Assert.False(updatedProp.IsNullable);
        Assert.Equal("updated_at_utc", updatedProp.GetColumnName());

        // Concurrency token
        var versionProp = entity.FindProperty(nameof(User.Version))!;
        Assert.True(versionProp.IsConcurrencyToken);
        Assert.Equal("version", versionProp.GetColumnName());

        // Check constraints
        var constraints = entity.GetCheckConstraints().Select(c => c.Name).ToHashSet();
        Assert.Contains("ck_users_status", constraints);
        Assert.Contains("ck_users_email_lowercase", constraints);
        Assert.Contains("ck_users_failed_login_attempts", constraints);
    }

    [Fact]
    public void UserSessionConfiguration_ConfiguresColumnsForeignKeysAndIndexesCorrectly()
    {
        var model = CreateModel();
        var entity = model.FindEntityType(typeof(UserSession))!;

        // Primary Key
        var pk = entity.FindPrimaryKey();
        Assert.NotNull(pk);
        Assert.Equal("pk_user_sessions", pk.GetName());

        // UserId FK
        var userFk = entity.GetForeignKeys().FirstOrDefault(fk => fk.PrincipalEntityType.ClrType == typeof(User));
        Assert.NotNull(userFk);
        Assert.Equal(DeleteBehavior.Cascade, userFk.DeleteBehavior);
        Assert.Equal("fk_user_sessions_users_user_id", userFk.GetConstraintName());

        // Timestamps
        var createdProp = entity.FindProperty(nameof(UserSession.CreatedAtUtc))!;
        Assert.False(createdProp.IsNullable);
        Assert.Equal("timestamp with time zone", createdProp.GetColumnType());

        var lastUsedProp = entity.FindProperty(nameof(UserSession.LastUsedAtUtc))!;
        Assert.False(lastUsedProp.IsNullable);
        Assert.Equal("last_used_at_utc", lastUsedProp.GetColumnName());
        Assert.Equal("timestamp with time zone", lastUsedProp.GetColumnType());

        var expiresProp = entity.FindProperty(nameof(UserSession.ExpiresAtUtc))!;
        Assert.False(expiresProp.IsNullable);
        Assert.Equal("expires_at_utc", expiresProp.GetColumnName());
        Assert.Equal("timestamp with time zone", expiresProp.GetColumnType());

        var revokedProp = entity.FindProperty(nameof(UserSession.RevokedAtUtc))!;
        Assert.True(revokedProp.IsNullable);
        Assert.Equal("revoked_at_utc", revokedProp.GetColumnName());

        // RevocationReason
        var reasonProp = entity.FindProperty(nameof(UserSession.RevocationReason))!;
        Assert.True(reasonProp.IsNullable);
        Assert.Equal("revocation_reason", reasonProp.GetColumnName());
        Assert.Equal(100, reasonProp.GetMaxLength());

        // Concurrency
        var versionProp = entity.FindProperty(nameof(UserSession.Version))!;
        Assert.True(versionProp.IsConcurrencyToken);

        // Ignored computed properties
        Assert.Null(entity.FindProperty("IsRevoked"));

        // Indexes
        var indexes = entity.GetIndexes().Select(i => i.GetDatabaseName()).ToHashSet();
        Assert.Contains("ix_user_sessions_user_id", indexes);
        Assert.Contains("ix_user_sessions_expires_at_utc", indexes);

        // Check constraint
        var constraints = entity.GetCheckConstraints().Select(c => c.Name).ToHashSet();
        Assert.Contains("ck_user_sessions_revocation_reason", constraints);
    }

    [Fact]
    public void RefreshTokenConfiguration_ConfiguresColumnsForeignKeysAndIndexesCorrectly()
    {
        var model = CreateModel();
        var entity = model.FindEntityType(typeof(RefreshToken))!;

        // Primary Key
        var pk = entity.FindPrimaryKey();
        Assert.NotNull(pk);
        Assert.Equal("pk_refresh_tokens", pk.GetName());

        // SessionId FK
        var sessionFk = entity.GetForeignKeys().FirstOrDefault(fk => fk.PrincipalEntityType.ClrType == typeof(UserSession));
        Assert.NotNull(sessionFk);
        Assert.Equal(DeleteBehavior.Cascade, sessionFk.DeleteBehavior);
        Assert.Equal("fk_refresh_tokens_user_sessions_session_id", sessionFk.GetConstraintName());

        // TokenHash & ReplacedByTokenHash
        var tokenHashProp = entity.FindProperty(nameof(RefreshToken.TokenHash))!;
        Assert.False(tokenHashProp.IsNullable);
        Assert.Equal("token_hash", tokenHashProp.GetColumnName());
        Assert.Equal(64, tokenHashProp.GetMaxLength());
        Assert.True(tokenHashProp.IsFixedLength());

        var replacedHashProp = entity.FindProperty(nameof(RefreshToken.ReplacedByTokenHash))!;
        Assert.True(replacedHashProp.IsNullable);
        Assert.Equal("replaced_by_token_hash", replacedHashProp.GetColumnName());
        Assert.Equal(64, replacedHashProp.GetMaxLength());
        Assert.True(replacedHashProp.IsFixedLength());

        // Unique index on TokenHash
        var hashIndex = entity.GetIndexes().FirstOrDefault(i => i.Properties.Any(p => p.Name == nameof(RefreshToken.TokenHash)));
        Assert.NotNull(hashIndex);
        Assert.True(hashIndex.IsUnique);
        Assert.Equal("ix_refresh_tokens_token_hash", hashIndex.GetDatabaseName());

        // Ignored computed properties
        Assert.Null(entity.FindProperty("IsRotated"));
        Assert.Null(entity.FindProperty("IsRevoked"));
        Assert.Null(entity.FindProperty("IsReplay"));

        // Check constraints
        var constraints = entity.GetCheckConstraints().Select(c => c.Name).ToHashSet();
        Assert.Contains("ck_refresh_tokens_token_hash", constraints);
        Assert.Contains("ck_refresh_tokens_replaced_by_token_hash", constraints);
    }

    [Fact]
    public void SecurityAuditEventConfiguration_ConfiguresZeroForeignKeysAndJsonbMetadata()
    {
        var model = CreateModel();
        var entity = model.FindEntityType(typeof(SecurityAuditEvent))!;

        // Primary Key
        var pk = entity.FindPrimaryKey();
        Assert.NotNull(pk);
        Assert.Equal("pk_security_audit_events", pk.GetName());

        // ZERO foreign keys to ensure permanent non-cascading durability
        Assert.Empty(entity.GetForeignKeys());

        // Client IP
        var ipProp = entity.FindProperty(nameof(SecurityAuditEvent.ClientIp))!;
        Assert.True(ipProp.IsNullable);
        Assert.Equal("client_ip", ipProp.GetColumnName());
        Assert.Equal(45, ipProp.GetMaxLength());

        // Metadata JSONB
        var metaProp = entity.FindProperty(nameof(SecurityAuditEvent.Metadata))!;
        Assert.True(metaProp.IsNullable);
        Assert.Equal("details_json", metaProp.GetColumnName());
        Assert.Equal("jsonb", metaProp.GetColumnType());
        Assert.NotNull(metaProp.GetValueConverter());

        // Ignored computed properties
        Assert.Null(entity.FindProperty("Reason"));
        Assert.Null(entity.FindProperty("DetectedLineage"));
        Assert.Null(entity.FindProperty("ActionTaken"));

        // Indexes
        var indexes = entity.GetIndexes().Select(i => i.GetDatabaseName()).ToHashSet();
        Assert.Contains("ix_security_audit_events_created_at_utc", indexes);
        Assert.Contains("ix_security_audit_events_user_id", indexes);
        Assert.Contains("ix_security_audit_events_session_id", indexes);

        // Check constraint
        var constraints = entity.GetCheckConstraints().Select(c => c.Name).ToHashSet();
        Assert.Contains("ck_security_audit_events_event_type", constraints);
    }

    [Fact]
    public void SecurityAuditMetadata_SerializationRoundTrip_HandlesValidMetadata()
    {
        var original = SecurityAuditMetadata.Create(
            SecurityAuditMetadata.Reasons.TokenReplay,
            SecurityAuditMetadata.Lineages.ReplayDetected,
            SecurityAuditMetadata.Actions.SessionRevoked);

        var json = SecurityAuditEventConfiguration.SerializeMetadata(original);
        Assert.NotNull(json);

        // Verify JSON camelCase property names
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal(SecurityAuditMetadata.Reasons.TokenReplay, root.GetProperty("reason").GetString());
        Assert.Equal(SecurityAuditMetadata.Lineages.ReplayDetected, root.GetProperty("detectedLineage").GetString());
        Assert.Equal(SecurityAuditMetadata.Actions.SessionRevoked, root.GetProperty("actionTaken").GetString());

        // Deserialize back
        var deserialized = SecurityAuditEventConfiguration.DeserializeMetadata(json);
        Assert.NotNull(deserialized);
        Assert.Equal(original.Reason, deserialized.Reason);
        Assert.Equal(original.DetectedLineage, deserialized.DetectedLineage);
        Assert.Equal(original.ActionTaken, deserialized.ActionTaken);
        Assert.Equal(original, deserialized);
    }

    [Fact]
    public void SecurityAuditMetadata_SerializationRoundTrip_HandlesNullMetadata()
    {
        var json = SecurityAuditEventConfiguration.SerializeMetadata(null);
        Assert.Null(json);

        var deserialized = SecurityAuditEventConfiguration.DeserializeMetadata(null);
        Assert.Null(deserialized);

        var emptyDeserialized = SecurityAuditEventConfiguration.DeserializeMetadata("   ");
        Assert.Null(emptyDeserialized);
    }

    [Fact]
    public void SecurityAuditMetadata_Deserialization_RejectsInvalidOrUnapprovedValues()
    {
        // Unapproved reason
        var badReasonJson = "{\"reason\":\"arbitrary_unapproved_reason\",\"detectedLineage\":null,\"actionTaken\":\"permit\"}";
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditEventConfiguration.DeserializeMetadata(badReasonJson));

        // Malformed lineage
        var badLineageJson = "{\"reason\":\"standard_login\",\"detectedLineage\":\"invalid-lineage-format\",\"actionTaken\":\"permit\"}";
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditEventConfiguration.DeserializeMetadata(badLineageJson));

        // Sensitive data pattern (e.g. password or phone)
        var sensitiveJson = "{\"reason\":\"standard_login\",\"detectedLineage\":\"+15551234567\",\"actionTaken\":\"permit\"}";
        Assert.Throws<ArgumentException>(() =>
            SecurityAuditEventConfiguration.DeserializeMetadata(sensitiveJson));
    }
}
