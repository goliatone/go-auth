ALTER TABLE users
    DROP COLUMN IF EXISTS suspended_at,
    DROP COLUMN IF EXISTS status;
