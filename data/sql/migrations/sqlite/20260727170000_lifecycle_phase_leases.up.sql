ALTER TABLE lifecycle_operations ADD COLUMN local_lease_owner TEXT;
ALTER TABLE lifecycle_operations ADD COLUMN local_lease_until TIMESTAMP;
ALTER TABLE lifecycle_operations ADD COLUMN freshness_lease_owner TEXT;
ALTER TABLE lifecycle_operations ADD COLUMN freshness_lease_until TIMESTAMP;
