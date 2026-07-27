CREATE TABLE oidc_states (
    state_hash BLOB NOT NULL PRIMARY KEY,
    provider_key TEXT NOT NULL,
    nonce TEXT NOT NULL,
    verifier_version INTEGER NOT NULL,
    verifier_algorithm TEXT NOT NULL,
    verifier_key_id TEXT NOT NULL,
    verifier_nonce BLOB NOT NULL,
    verifier_ciphertext BLOB NOT NULL,
    redirect_to TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    CONSTRAINT oidc_states_hash_length CHECK (length(state_hash) = 32),
    CONSTRAINT oidc_states_verifier_version CHECK (verifier_version > 0)
);

CREATE INDEX idx_oidc_states_expires_at ON oidc_states(expires_at);
