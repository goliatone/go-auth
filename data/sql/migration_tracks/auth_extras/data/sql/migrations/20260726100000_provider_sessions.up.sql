CREATE TABLE provider_sessions (
    id UUID NOT NULL PRIMARY KEY,
    local_session_id UUID NOT NULL UNIQUE,
    lookup_hash BYTEA NOT NULL UNIQUE,
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
    principal JSONB NOT NULL,
    status TEXT NOT NULL,
    token_revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    max_expires_at TIMESTAMPTZ NOT NULL,
    refresh_attempt_id TEXT,
    refresh_base_revision BIGINT,
    refresh_lease_until TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    remote_revocation_status TEXT,
    remote_revocation_retryable BOOLEAN NOT NULL DEFAULT FALSE,
    residual_access_expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT provider_sessions_lookup_hash_length CHECK (octet_length(lookup_hash) = 32),
    CONSTRAINT provider_sessions_status CHECK (status IN ('available', 'refreshing', 'uncertain', 'revoked', 'expired')),
    CONSTRAINT provider_sessions_revision CHECK (token_revision > 0),
    CONSTRAINT provider_sessions_expiry_order CHECK (idle_expires_at <= max_expires_at)
);

CREATE INDEX idx_provider_sessions_subject ON provider_sessions(application_subject);
CREATE INDEX idx_provider_sessions_binding ON provider_sessions(host, application_id, environment, provider, issuer, oauth_client_id);
CREATE INDEX idx_provider_sessions_cleanup ON provider_sessions(status, max_expires_at, revoked_at);
CREATE INDEX idx_provider_sessions_refresh_lease ON provider_sessions(status, refresh_lease_until);

CREATE TABLE provider_session_tokens (
    session_id UUID NOT NULL PRIMARY KEY,
    token_revision BIGINT NOT NULL,
    envelope_version SMALLINT NOT NULL,
    envelope_algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    access_expires_at TIMESTAMPTZ,
    refresh_expires_at TIMESTAMPTZ,
    retain_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES provider_sessions(id) ON DELETE CASCADE,
    CONSTRAINT provider_session_tokens_revision CHECK (token_revision > 0),
    CONSTRAINT provider_session_tokens_envelope_version CHECK (envelope_version > 0)
);

CREATE INDEX idx_provider_session_tokens_key ON provider_session_tokens(key_id);
CREATE INDEX idx_provider_session_tokens_retention ON provider_session_tokens(retain_until);
