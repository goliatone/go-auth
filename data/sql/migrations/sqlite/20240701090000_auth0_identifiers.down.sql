DROP TABLE IF EXISTS user_identifiers;
DROP INDEX IF EXISTS users_external_id_unique;

-- SQLite does not support dropping columns via ALTER TABLE.
-- No-op for users.external_id and users.external_id_provider.
