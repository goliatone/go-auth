ALTER TABLE lifecycle_operations
    DROP COLUMN local_lease_owner,
    DROP COLUMN local_lease_until,
    DROP COLUMN freshness_lease_owner,
    DROP COLUMN freshness_lease_until;
