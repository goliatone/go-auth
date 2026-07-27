package sync

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/auth0/go-auth0/management"
	auth "github.com/goliatone/go-auth"
	goerrors "github.com/goliatone/go-errors"
	"github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"

	_ "github.com/mattn/go-sqlite3"
)

func errorHasTextCode(err error, textCode string) bool {
	var richErr *goerrors.Error
	return errors.As(err, &richErr) && richErr.TextCode == textCode
}

const (
	sqliteCreateUsers = `CREATE TABLE users (
    id TEXT NOT NULL PRIMARY KEY,
    user_role TEXT NOT NULL DEFAULT 'member',
    status TEXT NOT NULL DEFAULT 'active',
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    profile_picture TEXT,
    email TEXT NOT NULL DEFAULT '',
    external_id TEXT,
    external_id_provider TEXT,
    phone_number TEXT,
    password_hash TEXT,
    is_email_verified INTEGER NOT NULL DEFAULT 0,
    login_attempts INTEGER NOT NULL DEFAULT 0,
    login_attempt_at TIMESTAMP NULL,
    loggedin_at TIMESTAMP NULL,
    suspended_at TIMESTAMP NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    reseted_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL,
    deleted_at TIMESTAMP NULL
);`
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

func TestIdentifierStoreUpsertIsImmutableAndIdempotent(t *testing.T) {
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
	require.Error(t, err)
	assert.True(t, errorHasTextCode(err, auth.TextCodeIdentifierConflict))

	found, err = store.FindUserID(ctx, "auth0", "auth0|user-123")
	require.NoError(t, err)
	assert.Equal(t, userID, found)

	err = store.Upsert(ctx, userID, "auth0", "auth0|user-123")
	require.NoError(t, err)
}

func TestIdentifierStoreFindUserIDNotFound(t *testing.T) {
	store, _, cleanup := setupIdentifierStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.FindUserID(ctx, "auth0", "auth0|missing")
	require.Error(t, err)
	assert.True(t, repository.IsRecordNotFound(err))
}

func TestIdentifierStoreDelete(t *testing.T) {
	store, bunDB, cleanup := setupIdentifierStore(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New().String()
	_, err := bunDB.Exec("INSERT INTO users (id) VALUES (?)", userID)
	require.NoError(t, err)

	err = store.Upsert(ctx, userID, "auth0", "auth0|user-123")
	require.NoError(t, err)

	err = store.Delete(ctx, userID, "auth0", "auth0|user-123")
	require.NoError(t, err)

	_, err = store.FindUserID(ctx, "auth0", "auth0|user-123")
	require.Error(t, err)
	assert.True(t, repository.IsRecordNotFound(err))
}

func TestIdentifierStoreCreateUserAndBindRollsBackOnConflict(t *testing.T) {
	store, bunDB, cleanup := setupIdentifierStore(t)
	defer cleanup()
	ctx := context.Background()
	users := transactionalTestUsers{}

	first := &auth.User{ID: uuid.New()}
	created, err := store.CreateUserAndBind(ctx, users, first, "auth0", "auth0|subject")
	require.NoError(t, err)
	require.Equal(t, first.ID, created.ID)

	second := &auth.User{ID: uuid.New()}
	_, err = store.CreateUserAndBind(ctx, users, second, "auth0", "auth0|subject")
	require.Error(t, err)
	assert.True(t, errorHasTextCode(err, auth.TextCodeIdentifierConflict))

	var count int
	require.NoError(t, bunDB.NewSelect().
		Table("users").
		ColumnExpr("COUNT(*)").
		Where("id = ?", second.ID.String()).
		Scan(ctx, &count))
	assert.Zero(t, count, "conflicting user creation must roll back")

	found, err := store.FindUserID(ctx, "auth0", "auth0|subject")
	require.NoError(t, err)
	assert.Equal(t, first.ID.String(), found)
}

func TestIdentifierStoreUpsertUserAndBindRollsBackOnConflict(t *testing.T) {
	store, bunDB, cleanup := setupIdentifierStore(t)
	defer cleanup()
	ctx := context.Background()
	users := transactionalTestUsers{}

	first := &auth.User{ID: uuid.New()}
	_, err := store.UpsertUserAndBind(ctx, users, first, "auth0", "auth0|subject")
	require.NoError(t, err)

	second := &auth.User{ID: uuid.New()}
	_, err = store.UpsertUserAndBind(ctx, users, second, "auth0", "auth0|subject")
	require.Error(t, err)
	assert.True(t, errorHasTextCode(err, auth.TextCodeIdentifierConflict))

	var count int
	require.NoError(t, bunDB.NewSelect().
		Table("users").
		ColumnExpr("COUNT(*)").
		Where("id = ?", second.ID.String()).
		Scan(ctx, &count))
	assert.Zero(t, count, "conflicting sync upsert must roll back")
}

func TestIdentifierStoreConcurrentCreateAndBindLeavesOneUser(t *testing.T) {
	store, bunDB, cleanup := setupIdentifierStore(t)
	defer cleanup()
	ctx := context.Background()
	users := transactionalTestUsers{}

	const attempts = 8
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for range attempts {
		user := &auth.User{ID: uuid.New()}
		go func() {
			defer wg.Done()
			_, err := store.CreateUserAndBind(ctx, users, user, "auth0", "auth0|concurrent")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	successes := 0
	conflicts := 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errorHasTextCode(err, auth.TextCodeIdentifierConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent bind error: %v", err)
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, attempts-1, conflicts)

	var userCount, identifierCount int
	require.NoError(t, bunDB.NewSelect().Table("users").ColumnExpr("COUNT(*)").Scan(ctx, &userCount))
	require.NoError(t, bunDB.NewSelect().Table("user_identifiers").ColumnExpr("COUNT(*)").Scan(ctx, &identifierCount))
	assert.Equal(t, 1, userCount)
	assert.Equal(t, 1, identifierCount)
}

func TestIdentifierStoreConcurrentUpsertAndBindLeavesOneUser(t *testing.T) {
	store, bunDB, cleanup := setupIdentifierStore(t)
	defer cleanup()
	ctx := context.Background()
	users := transactionalTestUsers{}

	const attempts = 8
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for range attempts {
		user := &auth.User{ID: uuid.New()}
		go func() {
			defer wg.Done()
			_, err := store.UpsertUserAndBind(ctx, users, user, "auth0", "auth0|concurrent-sync")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	successes := 0
	conflicts := 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errorHasTextCode(err, auth.TextCodeIdentifierConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent sync error: %v", err)
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, attempts-1, conflicts)

	var userCount, identifierCount int
	require.NoError(t, bunDB.NewSelect().Table("users").ColumnExpr("COUNT(*)").Scan(ctx, &userCount))
	require.NoError(t, bunDB.NewSelect().Table("user_identifiers").ColumnExpr("COUNT(*)").Scan(ctx, &identifierCount))
	assert.Equal(t, 1, userCount)
	assert.Equal(t, 1, identifierCount)
}

func TestServiceSyncUserFailsClosedBeforeMutationOnIdentifierLookupError(t *testing.T) {
	lookupErr := errors.New("identifier store unavailable")
	store := &failingSyncIdentifierStore{lookupErr: lookupErr}
	service := NewService(Config{
		Users:           &embeddedUsers{},
		IdentifierStore: store,
		UserMapper: func(context.Context, *management.User) (*auth.User, error) {
			return &auth.User{ID: uuid.New(), Status: auth.UserStatusActive}, nil
		},
	})
	subject := "auth0|subject"
	_, err := service.SyncUser(context.Background(), &management.User{ID: &subject})
	require.ErrorIs(t, err, lookupErr)
	assert.Zero(t, store.syncCalls)
}

func TestServiceSyncUserPreservesMappedLocalRoleAndLifecycle(t *testing.T) {
	store, bunDB, cleanup := setupIdentifierStore(t)
	defer cleanup()
	ctx := context.Background()
	userID := uuid.New()
	subject := "auth0|suspended-user"
	_, err := bunDB.Exec(`
		INSERT INTO users (
			id, user_role, status, first_name, last_name, username, email,
			is_email_verified, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, userID.String(), auth.RoleAdmin, auth.UserStatusSuspended,
		"Old", "Name", "old-name", "old@example.com", true, "{}")
	require.NoError(t, err)
	require.NoError(t, store.Bind(ctx, userID.String(), "auth0", subject))

	users := auth.NewUsersRepository(bunDB)
	service := NewService(Config{Users: users, IdentifierStore: store})
	email := "new@example.com"
	name := "New Name"
	nickname := "new-name"
	emailVerified := false
	appMetadata := map[string]any{"role": string(auth.RoleOwner)}
	synced, err := service.SyncUser(ctx, &management.User{
		ID:            &subject,
		Email:         &email,
		Name:          &name,
		Nickname:      &nickname,
		EmailVerified: &emailVerified,
		AppMetadata:   &appMetadata,
	})
	if err != nil {
		t.Fatalf("sync mapped user: %v (cause: %v)", err, errors.Unwrap(err))
	}
	require.Equal(t, auth.UserStatusSuspended, synced.Status)
	require.Equal(t, auth.RoleAdmin, synced.Role)
	require.Equal(t, "New", synced.FirstName)
	require.Equal(t, email, synced.Email)
	require.False(t, synced.EmailValidated)

	var status string
	var role string
	var storedEmailVerified bool
	require.NoError(t, bunDB.QueryRow(
		"SELECT status, user_role, is_email_verified FROM users WHERE id = ?",
		userID.String(),
	).Scan(&status, &role, &storedEmailVerified))
	require.Equal(t, string(auth.UserStatusSuspended), status)
	require.Equal(t, string(auth.RoleAdmin), role)
	require.False(t, storedEmailVerified)
}

type transactionalTestUsers struct {
	auth.Users
}

func (transactionalTestUsers) CreateTx(ctx context.Context, tx bun.IDB, record *auth.User, _ ...repository.InsertCriteria) (*auth.User, error) {
	_, err := tx.NewRaw("INSERT INTO users (id) VALUES (?)", record.ID.String()).Exec(ctx)
	if err != nil {
		return nil, err
	}
	return record, nil
}

func (transactionalTestUsers) UpsertTx(ctx context.Context, tx bun.IDB, record *auth.User, _ ...repository.UpdateCriteria) (*auth.User, error) {
	if record.ID == uuid.Nil {
		record.ID = uuid.New()
	}
	_, err := tx.NewRaw("INSERT INTO users (id) VALUES (?) ON CONFLICT(id) DO NOTHING", record.ID.String()).Exec(ctx)
	if err != nil {
		return nil, err
	}
	return record, nil
}

type embeddedUsers struct {
	auth.Users
}

type failingSyncIdentifierStore struct {
	auth.TransactionalIdentifierSyncStore
	lookupErr error
	syncCalls int
}

func (s *failingSyncIdentifierStore) FindUserID(context.Context, string, string) (string, error) {
	return "", s.lookupErr
}

func (s *failingSyncIdentifierStore) UpsertUserAndBind(
	context.Context,
	auth.Users,
	*auth.User,
	string,
	string,
) (*auth.User, error) {
	s.syncCalls++
	return nil, nil
}
