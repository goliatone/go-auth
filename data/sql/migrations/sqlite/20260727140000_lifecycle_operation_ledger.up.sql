CREATE TABLE lifecycle_operations (
    operation_id TEXT NOT NULL PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    action TEXT NOT NULL,
    local_phase TEXT NOT NULL,
    remote_phase TEXT NOT NULL,
    freshness_phase TEXT NOT NULL,
    local_status TEXT,
    local_session_effect TEXT,
    remote_status TEXT,
    remote_retryable BOOLEAN NOT NULL DEFAULT FALSE,
    remote_request_fingerprint TEXT,
    remote_session_effect TEXT,
    remote_residual_access_expires_at TIMESTAMP,
    freshness_status TEXT,
    provider_idempotency_key TEXT NOT NULL,
    remote_attempt INTEGER NOT NULL DEFAULT 0,
    remote_lease_owner TEXT,
    remote_lease_until TIMESTAMP,
    revision INTEGER NOT NULL DEFAULT 1,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT lifecycle_operations_revision CHECK (revision > 0),
    CONSTRAINT lifecycle_operations_remote_attempt CHECK (remote_attempt >= 0)
);

CREATE INDEX idx_lifecycle_operations_pending
    ON lifecycle_operations(remote_phase, remote_lease_until, updated_at);
