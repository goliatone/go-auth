CREATE TABLE users (
	id TEXT NOT NULL PRIMARY KEY,
	user_role TEXT NOT NULL DEFAULT 'guest' CHECK (
		user_role IN ('guest', 'member', 'admin', 'owner')
	),
	first_name TEXT NOT NULL,
	last_name TEXT NOT NULL,
	username TEXT NOT NULL,
	profile_picture TEXT,
	email TEXT NOT NULL UNIQUE,
	-- phone_number TEXT NULL UNIQUE,
	phone_number TEXT,
	password_hash TEXT,
	-- metadata TEXT NOT NULL DEFAULT '{}',
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
	is_email_verified BOOLEAN DEFAULT FALSE,
	login_attempts INTEGER DEFAULT 0,
	login_attempt_at TIMESTAMP NULL,
	loggedin_at TIMESTAMP NULL,
	reseted_at  TIMESTAMP NULL,
	created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	deleted_at  TIMESTAMP,
	updated_at  TIMESTAMP
);

CREATE UNIQUE INDEX users_username_unique ON users(username);
CREATE INDEX users_username_index ON users(username);
CREATE UNIQUE INDEX users_email_unique ON users(email);
CREATE INDEX users_email_index ON users(email);
CREATE INDEX users_is_email_verified_index ON users(is_email_verified);

---bun:split

CREATE TABLE password_reset (
	id TEXT NOT NULL PRIMARY KEY,
	user_id TEXT NOT NULL,
	email TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'unknown' CHECK (
		status IN ('unknown', 'requested', 'expired', 'changed')
	),
	reseted_at TIMESTAMP,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	deleted_at TIMESTAMP,
	updated_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE
);
