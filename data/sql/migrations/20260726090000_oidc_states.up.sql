CREATE TABLE oidc_states (
    state_hash BYTEA NOT NULL PRIMARY KEY,
    provider_key TEXT NOT NULL,
    nonce TEXT NOT NULL,
    verifier_version SMALLINT NOT NULL,
    verifier_algorithm TEXT NOT NULL,
    verifier_key_id TEXT NOT NULL,
    verifier_nonce BYTEA NOT NULL,
    verifier_ciphertext BYTEA NOT NULL,
    redirect_to TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT oidc_states_hash_length CHECK (octet_length(state_hash) = 32),
    CONSTRAINT oidc_states_verifier_version CHECK (verifier_version > 0)
);

CREATE INDEX idx_oidc_states_expires_at ON oidc_states(expires_at);
