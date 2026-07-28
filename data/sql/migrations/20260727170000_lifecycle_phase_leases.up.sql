ALTER TABLE lifecycle_operations
    ADD COLUMN local_lease_owner TEXT,
    ADD COLUMN local_lease_until TIMESTAMPTZ,
    ADD COLUMN freshness_lease_owner TEXT,
    ADD COLUMN freshness_lease_until TIMESTAMPTZ;
