DROP TABLE IF EXISTS user_identifiers;

DROP INDEX IF EXISTS users_external_id_unique;

ALTER TABLE users
    DROP COLUMN IF EXISTS external_id,
    DROP COLUMN IF EXISTS external_id_provider;
