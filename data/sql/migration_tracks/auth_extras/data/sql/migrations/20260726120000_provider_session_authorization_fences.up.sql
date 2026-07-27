CREATE TABLE provider_session_authorization_fences (
    application_subject TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '',
    required_permission_version TEXT NOT NULL DEFAULT '',
    permission_version_observed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (application_subject, tenant_id)
);

CREATE INDEX idx_provider_session_authorization_fences_updated
    ON provider_session_authorization_fences(updated_at);
