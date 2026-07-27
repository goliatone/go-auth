CREATE INDEX idx_provider_sessions_tenant_status
    ON provider_sessions(tenant_id, status, id);
CREATE INDEX idx_provider_sessions_subject_tenant_status
    ON provider_sessions(application_subject, tenant_id, status, id);
