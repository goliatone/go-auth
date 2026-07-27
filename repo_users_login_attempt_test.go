package auth_test

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

func TestUsersReserveLoginAttemptIsAtomicAtThreshold(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", "file:"+t.TempDir()+"/login-attempts.db?_busy_timeout=10000&_journal_mode=WAL")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	sqlDB.SetMaxOpenConns(10)

	db := bun.NewDB(sqlDB, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`
		CREATE TABLE users (
			id TEXT NOT NULL PRIMARY KEY,
			login_attempts INTEGER NOT NULL DEFAULT 0,
			login_attempt_at TIMESTAMP NULL,
			deleted_at TIMESTAMP NULL
		)
	`)
	require.NoError(t, err)

	userID := uuid.New()
	_, err = db.Exec(`INSERT INTO users (id) VALUES (?)`, userID.String())
	require.NoError(t, err)

	users := auth.NewUsersRepository(db)
	attemptTracker, ok := users.(auth.AtomicLoginAttemptTracker)
	require.True(t, ok)
	policy := auth.LoginAttemptPolicy{MaxAttempts: 5, Window: time.Hour}
	var allowed atomic.Int32
	errs := make(chan error, 20)
	var wg sync.WaitGroup

	for range 20 {
		wg.Go(func() {
			result, reserveErr := attemptTracker.ReserveLoginAttempt(context.Background(), userID, policy)
			if reserveErr != nil {
				errs <- reserveErr
				return
			}
			if result.Allowed {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	close(errs)
	for reserveErr := range errs {
		require.NoError(t, reserveErr)
	}
	require.Equal(t, int32(policy.MaxAttempts), allowed.Load())

	var attempts int
	require.NoError(t, db.QueryRow(`SELECT login_attempts FROM users WHERE id = ?`, userID.String()).Scan(&attempts))
	require.Equal(t, policy.MaxAttempts, attempts)

	_, err = db.Exec(
		`UPDATE users SET login_attempts = ?, login_attempt_at = ? WHERE id = ?`,
		policy.MaxAttempts,
		time.Now().UTC().Add(-2*policy.Window),
		userID.String(),
	)
	require.NoError(t, err)
	result, err := attemptTracker.ReserveLoginAttempt(context.Background(), userID, policy)
	require.NoError(t, err)
	require.True(t, result.Allowed)
	require.Equal(t, 1, result.Attempts)
}
