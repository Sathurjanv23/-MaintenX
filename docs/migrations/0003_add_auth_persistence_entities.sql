-- ==============================================================================
-- MaintenX Database Migration: 0003_add_auth_persistence_entities.sql
-- Description: Idempotent SQL script creating authentication tables:
--              platform.users, platform.user_sessions, platform.refresh_tokens,
--              and platform.security_audit_events with check constraints,
--              indexes, and cascade deletion rules.
-- ==============================================================================

DO $EF$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM platform."__EFMigrationsHistory" WHERE "MigrationId" = '20261114000000_AddAuthPersistenceEntities') THEN

        -- 1. Create platform.users table
        CREATE TABLE platform.users (
            id uuid NOT NULL,
            email character varying(256) NOT NULL,
            password_hash character varying(500) NOT NULL,
            security_stamp character varying(64) NOT NULL,
            status character varying(50) NOT NULL,
            failed_login_attempts integer NOT NULL DEFAULT 0,
            failed_login_window_started_at_utc timestamp with time zone,
            lockout_end_utc timestamp with time zone,
            last_login_at_utc timestamp with time zone,
            created_at_utc timestamp with time zone NOT NULL,
            updated_at_utc timestamp with time zone NOT NULL,
            version bigint NOT NULL,
            CONSTRAINT pk_users PRIMARY KEY (id),
            CONSTRAINT ck_users_status CHECK (status IN ('Active', 'Suspended', 'Deactivated')),
            CONSTRAINT ck_users_email_lowercase CHECK (email = lower(email)),
            CONSTRAINT ck_users_failed_login_attempts CHECK (failed_login_attempts >= 0)
        );

        CREATE UNIQUE INDEX ix_users_email ON platform.users (email);

        -- 2. Create platform.user_sessions table
        CREATE TABLE platform.user_sessions (
            id uuid NOT NULL,
            user_id uuid NOT NULL,
            created_at_utc timestamp with time zone NOT NULL,
            last_used_at_utc timestamp with time zone NOT NULL,
            expires_at_utc timestamp with time zone NOT NULL,
            revoked_at_utc timestamp with time zone,
            revocation_reason character varying(100),
            version bigint NOT NULL,
            CONSTRAINT pk_user_sessions PRIMARY KEY (id),
            CONSTRAINT ck_user_sessions_revocation_reason CHECK (revocation_reason IS NULL OR revocation_reason IN ('UserLogout', 'PasswordChanged', 'SecurityStampMismatch', 'AccountSuspended', 'AccountDeactivated', 'TokenReplayDetected', 'AdminRevoked', 'Expired')),
            CONSTRAINT fk_user_sessions_users_user_id FOREIGN KEY (user_id) REFERENCES platform.users (id) ON DELETE CASCADE
        );

        CREATE INDEX ix_user_sessions_user_id ON platform.user_sessions (user_id);
        CREATE INDEX ix_user_sessions_expires_at_utc ON platform.user_sessions (expires_at_utc);

        -- 3. Create platform.refresh_tokens table
        CREATE TABLE platform.refresh_tokens (
            id uuid NOT NULL,
            session_id uuid NOT NULL,
            token_hash character(64) NOT NULL,
            replaced_by_token_hash character(64),
            created_at_utc timestamp with time zone NOT NULL,
            expires_at_utc timestamp with time zone NOT NULL,
            revoked_at_utc timestamp with time zone,
            CONSTRAINT pk_refresh_tokens PRIMARY KEY (id),
            CONSTRAINT ck_refresh_tokens_token_hash CHECK (token_hash ~ '^[a-f0-9]{64}$'),
            CONSTRAINT ck_refresh_tokens_replaced_by_token_hash CHECK (replaced_by_token_hash IS NULL OR replaced_by_token_hash ~ '^[a-f0-9]{64}$'),
            CONSTRAINT fk_refresh_tokens_user_sessions_session_id FOREIGN KEY (session_id) REFERENCES platform.user_sessions (id) ON DELETE CASCADE
        );

        CREATE UNIQUE INDEX ix_refresh_tokens_token_hash ON platform.refresh_tokens (token_hash);
        CREATE INDEX ix_refresh_tokens_session_id ON platform.refresh_tokens (session_id);
        CREATE INDEX ix_refresh_tokens_expires_at_utc ON platform.refresh_tokens (expires_at_utc);

        -- 4. Create platform.security_audit_events table
        CREATE TABLE platform.security_audit_events (
            id uuid NOT NULL,
            event_type character varying(50) NOT NULL,
            user_id uuid,
            session_id uuid,
            client_ip character varying(45),
            details_json jsonb,
            created_at_utc timestamp with time zone NOT NULL,
            CONSTRAINT pk_security_audit_events PRIMARY KEY (id),
            CONSTRAINT ck_security_audit_events_event_type CHECK (event_type IN ('UserRegistered', 'LoginSuccess', 'LoginFailed', 'AccountLockedOut', 'TokenRefreshed', 'TokenReplayDetected', 'SessionRevoked', 'PasswordChanged', 'SecurityStampRotated', 'UserSuspended', 'UserReactivated', 'UserDeactivated'))
        );

        CREATE INDEX ix_security_audit_events_created_at_utc ON platform.security_audit_events (created_at_utc);
        CREATE INDEX ix_security_audit_events_user_id ON platform.security_audit_events (user_id);
        CREATE INDEX ix_security_audit_events_session_id ON platform.security_audit_events (session_id);

        -- Record migration completion in history table
        INSERT INTO platform."__EFMigrationsHistory" ("MigrationId", "ProductVersion")
        VALUES ('20261114000000_AddAuthPersistenceEntities', '10.0.0');

    END IF;
END $EF$;
