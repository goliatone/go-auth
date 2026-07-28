CREATE TABLE provider_session_lifecycle_fences (
    application_subject TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '',
    blocked_state TEXT NOT NULL DEFAULT 'active',
    credentials_not_before TIMESTAMP,
    event_observed_at TIMESTAMP,
    generation INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (application_subject, tenant_id),
    CONSTRAINT provider_session_lifecycle_fences_state
        CHECK (blocked_state IN ('active', 'suspended', 'disabled', 'archived')),
    CONSTRAINT provider_session_lifecycle_fences_generation CHECK (generation >= 0)
);

CREATE INDEX idx_provider_session_lifecycle_fences_updated
    ON provider_session_lifecycle_fences(updated_at);
