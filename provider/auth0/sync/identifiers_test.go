package sync

import (
	"context"
	"database/sql"
	"testing"

	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"

	_ "github.com/mattn/go-sqlite3"
)

const (
	sqliteCreateUsers           = "CREATE TABLE users (id TEXT NOT NULL PRIMARY KEY);"
	sqliteCreateUserIdentifiers = `CREATE TABLE user_identifiers (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    identifier TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT uq_user_identifiers_provider_id UNIQUE (provider, identifier)
);`
	sqliteCreateUserIdentifiersIndex = "CREATE INDEX idx_user_identifiers_user_provider ON user_identifiers(user_id, provider);"
)

func setupIdentifierStore(t *testing.T) (*IdentifierStore, *bun.DB, func()) {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)

	bunDB := bun.NewDB(db, sqlitedialect.New())

	_, err = bunDB.Exec("PRAGMA foreign_keys = ON;")
	require.NoError(t, err)

	_, err = bunDB.Exec(sqliteCreateUsers)
	require.NoError(t, err)
	_, err = bunDB.Exec(sqliteCreateUserIdentifiers)
	require.NoError(t, err)
	_, err = bunDB.Exec(sqliteCreateUserIdentifiersIndex)
	require.NoError(t, err)

	cleanup := func() {
		_ = bunDB.Close()
		_ = db.Close()
	}

	return NewIdentifierStore(bunDB), bunDB, cleanup
}

func TestIdentifierStoreUpsertAndFind(t *testing.T) {
	store, bunDB, cleanup := setupIdentifierStore(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New().String()
	userID2 := uuid.New().String()

	_, err := bunDB.Exec("INSERT INTO users (id) VALUES (?)", userID)
	require.NoError(t, err)
	_, err = bunDB.Exec("INSERT INTO users (id) VALUES (?)", userID2)
	require.NoError(t, err)

	err = store.Upsert(ctx, userID, "auth0", "auth0|user-123")
	require.NoError(t, err)

	found, err := store.FindUserID(ctx, "auth0", "auth0|user-123")
	require.NoError(t, err)
	assert.Equal(t, userID, found)

	err = store.Upsert(ctx, userID2, "auth0", "auth0|user-123")
	require.NoError(t, err)

	found, err = store.FindUserID(ctx, "auth0", "auth0|user-123")
	require.NoError(t, err)
	assert.Equal(t, userID2, found)
}

func TestIdentifierStoreFindUserIDNotFound(t *testing.T) {
	store, _, cleanup := setupIdentifierStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.FindUserID(ctx, "auth0", "auth0|missing")
	require.Error(t, err)
	assert.True(t, repository.IsRecordNotFound(err))
}
