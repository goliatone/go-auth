PRAGMA foreign_keys = OFF;

CREATE TABLE password_reset_new (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown' CHECK (
        status IN ('unknown', 'requested', 'processing', 'expired', 'changed')
    ),
    reseted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    updated_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

INSERT INTO password_reset_new (
    id,
    user_id,
    email,
    status,
    reseted_at,
    created_at,
    deleted_at,
    updated_at
)
SELECT
    id,
    user_id,
    email,
    status,
    reseted_at,
    created_at,
    deleted_at,
    updated_at
FROM password_reset;

DROP TABLE password_reset;
ALTER TABLE password_reset_new RENAME TO password_reset;

PRAGMA foreign_keys = ON;
