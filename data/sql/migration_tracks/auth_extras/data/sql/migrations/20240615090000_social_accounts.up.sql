CREATE TABLE social_accounts (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email TEXT,
    name TEXT,
    username TEXT,
    avatar_url TEXT,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP NULL,
    profile_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT uq_social_accounts_provider_id UNIQUE (provider, provider_user_id),
    CONSTRAINT uq_social_accounts_user_provider UNIQUE (user_id, provider)
);

CREATE INDEX idx_social_accounts_user_id ON social_accounts(user_id);
CREATE INDEX idx_social_accounts_provider ON social_accounts(provider, provider_user_id);
