CREATE TABLE provider_sessions (
    id TEXT NOT NULL PRIMARY KEY,
    local_session_id TEXT NOT NULL UNIQUE,
    lookup_hash BLOB NOT NULL UNIQUE,
    application_subject TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    provider_session_id TEXT,
    host TEXT NOT NULL,
    application_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL,
    issuer TEXT NOT NULL,
    oauth_client_id TEXT NOT NULL,
    principal TEXT NOT NULL,
    status TEXT NOT NULL,
    token_revision INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    idle_expires_at TIMESTAMP NOT NULL,
    max_expires_at TIMESTAMP NOT NULL,
    refresh_attempt_id TEXT,
    refresh_base_revision INTEGER,
    refresh_lease_until TIMESTAMP,
    revoked_at TIMESTAMP,
    revocation_reason TEXT,
    remote_revocation_status TEXT,
    remote_revocation_retryable INTEGER NOT NULL DEFAULT 0,
    residual_access_expires_at TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT provider_sessions_lookup_hash_length CHECK (length(lookup_hash) = 32),
    CONSTRAINT provider_sessions_status CHECK (status IN ('available', 'refreshing', 'uncertain', 'revoked', 'expired')),
    CONSTRAINT provider_sessions_revision CHECK (token_revision > 0),
    CONSTRAINT provider_sessions_expiry_order CHECK (idle_expires_at <= max_expires_at)
);

CREATE INDEX idx_provider_sessions_subject ON provider_sessions(application_subject);
CREATE INDEX idx_provider_sessions_binding ON provider_sessions(host, application_id, environment, provider, issuer, oauth_client_id);
CREATE INDEX idx_provider_sessions_cleanup ON provider_sessions(status, max_expires_at, revoked_at);
CREATE INDEX idx_provider_sessions_refresh_lease ON provider_sessions(status, refresh_lease_until);

CREATE TABLE provider_session_tokens (
    session_id TEXT NOT NULL PRIMARY KEY,
    token_revision INTEGER NOT NULL,
    envelope_version INTEGER NOT NULL,
    envelope_algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    access_expires_at TIMESTAMP,
    refresh_expires_at TIMESTAMP,
    retain_until TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES provider_sessions(id) ON DELETE CASCADE,
    CONSTRAINT provider_session_tokens_revision CHECK (token_revision > 0),
    CONSTRAINT provider_session_tokens_envelope_version CHECK (envelope_version > 0)
);

CREATE INDEX idx_provider_session_tokens_key ON provider_session_tokens(key_id);
CREATE INDEX idx_provider_session_tokens_retention ON provider_session_tokens(retain_until);
