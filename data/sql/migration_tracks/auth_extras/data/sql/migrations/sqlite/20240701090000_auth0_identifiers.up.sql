CREATE TABLE user_identifiers (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    identifier TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT uq_user_identifiers_provider_id UNIQUE (provider, identifier)
);

CREATE INDEX idx_user_identifiers_user_provider ON user_identifiers(user_id, provider);

ALTER TABLE users ADD COLUMN external_id TEXT;
ALTER TABLE users ADD COLUMN external_id_provider TEXT;

CREATE UNIQUE INDEX users_external_id_unique
    ON users (external_id_provider, external_id);
