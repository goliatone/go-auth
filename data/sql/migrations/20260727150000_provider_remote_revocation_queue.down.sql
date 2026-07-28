DROP INDEX IF EXISTS idx_provider_sessions_remote_revocation_queue;

ALTER TABLE provider_sessions
    DROP COLUMN remote_revocation_attempt_count,
    DROP COLUMN remote_revocation_next_attempt_at,
    DROP COLUMN remote_revocation_lease_owner,
    DROP COLUMN remote_revocation_lease_until,
    DROP COLUMN remote_revocation_revision,
    DROP COLUMN remote_revocation_safe_error_code,
    DROP COLUMN remote_revocation_work_expires_at,
    DROP COLUMN remote_revocation_terminal_at;
