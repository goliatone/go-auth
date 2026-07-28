ALTER TABLE provider_sessions ADD COLUMN remote_revocation_attempt_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_sessions ADD COLUMN remote_revocation_next_attempt_at TIMESTAMP;
ALTER TABLE provider_sessions ADD COLUMN remote_revocation_lease_owner TEXT;
ALTER TABLE provider_sessions ADD COLUMN remote_revocation_lease_until TIMESTAMP;
ALTER TABLE provider_sessions ADD COLUMN remote_revocation_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_sessions ADD COLUMN remote_revocation_safe_error_code TEXT;
ALTER TABLE provider_sessions ADD COLUMN remote_revocation_work_expires_at TIMESTAMP;
ALTER TABLE provider_sessions ADD COLUMN remote_revocation_terminal_at TIMESTAMP;

CREATE INDEX idx_provider_sessions_remote_revocation_queue
    ON provider_sessions(
        remote_revocation_retryable,
        remote_revocation_next_attempt_at,
        remote_revocation_lease_until
    );
