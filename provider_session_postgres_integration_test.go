package auth_test

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	authrepo "github.com/goliatone/go-auth/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

func TestProviderSessionsPostgresCrossReplicaAndDurableState(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("GO_AUTH_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set GO_AUTH_TEST_POSTGRES_DSN to run provider-session Postgres integration")
	}
	sqlDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	schemaName := "goauth_ps_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = sqlDB.Exec(`CREATE SCHEMA "` + schemaName + `"`)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`SET search_path TO "` + schemaName + `"`)
	require.NoError(t, err)
	db := bun.NewDB(sqlDB, pgdialect.New())
	t.Cleanup(func() {
		_, _ = sqlDB.Exec(`SET search_path TO public`)
		_, _ = sqlDB.Exec(`DROP SCHEMA IF EXISTS "` + schemaName + `" CASCADE`)
		_ = db.Close()
	})
	for _, name := range []string{
		"20260726090000_oidc_states.up.sql",
		"20260726100000_provider_sessions.up.sql",
		"20260726120000_provider_session_authorization_fences.up.sql",
	} {
		raw, readErr := fs.ReadFile(auth.GetAuthExtrasMigrationsFS(), "data/sql/migrations/"+name)
		require.NoError(t, readErr)
		_, execErr := db.Exec(string(raw))
		require.NoError(t, execErr)
	}

	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)

	stateA, err := authrepo.NewOIDCStateStore(db, tokenCipher)
	require.NoError(t, err)
	stateB, err := authrepo.NewOIDCStateStore(db, tokenCipher)
	require.NoError(t, err)
	stateRecord := oidc.StateRecord{
		State: "postgres-state", Nonce: "nonce", CodeVerifier: "postgres-verifier",
		ProviderKey: "oidc", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	require.NoError(t, stateA.Save(context.Background(), stateRecord))
	consumed, err := stateB.Consume(context.Background(), stateRecord.State)
	require.NoError(t, err)
	require.Equal(t, stateRecord.CodeVerifier, consumed.CodeVerifier)
	_, err = stateA.Consume(context.Background(), stateRecord.State)
	require.ErrorIs(t, err, oidc.ErrInvalidState)

	repoA, err := authrepo.NewProviderSessionRepository(db)
	require.NoError(t, err)
	repoB, err := authrepo.NewProviderSessionRepository(db)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	refresher := &blockingProviderRefresher{started: make(chan struct{}), release: make(chan struct{})}
	managerA, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repoA, Cipher: tokenCipher, Binding: binding, Refresher: refresher,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour, RefreshLease: 5 * time.Second,
	})
	require.NoError(t, err)
	managerB, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repoB, Cipher: tokenCipher, Binding: binding, Refresher: refresher,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour, RefreshLease: 5 * time.Second,
	})
	require.NoError(t, err)
	created, err := managerA.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)

	results := make(chan error, 2)
	go func() {
		session, refreshErr := managerA.RefreshProviderSession(context.Background(), created.Handle, binding)
		if refreshErr == nil && session.TokenRevision != 2 {
			refreshErr = fmt.Errorf("manager A revision = %d", session.TokenRevision)
		}
		results <- refreshErr
	}()
	<-refresher.started
	go func() {
		session, refreshErr := managerB.RefreshProviderSession(context.Background(), created.Handle, binding)
		if refreshErr == nil && session.TokenRevision != 2 {
			refreshErr = fmt.Errorf("manager B revision = %d", session.TokenRevision)
		}
		results <- refreshErr
	}()
	_, err = db.Exec(
		"UPDATE provider_sessions SET updated_at = ? WHERE id = ?",
		time.Now().UTC().Add(-48*time.Hour),
		created.Session.ID,
	)
	require.NoError(t, err)
	cleanupDuringRefresh, err := repoB.Cleanup(context.Background(), auth.ProviderSessionCleanupPolicy{
		Now:              time.Now().UTC(),
		TokenRetention:   time.Hour,
		SessionRetention: 24 * time.Hour,
		BatchSize:        10,
	})
	require.NoError(t, err)
	require.Zero(t, cleanupDuringRefresh.TokenRecords)
	require.Zero(t, cleanupDuringRefresh.SessionRecords)
	time.Sleep(30 * time.Millisecond)
	close(refresher.release)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	require.EqualValues(t, 1, refresher.calls.Load())

	_, changed, err := repoA.Revoke(context.Background(), created.Session.ID, "cleanup boundary")
	require.NoError(t, err)
	require.True(t, changed)
	cleanupNow := time.Now().UTC().Truncate(time.Second)
	_, err = db.Exec(
		"UPDATE provider_sessions SET updated_at = ? WHERE id = ?",
		cleanupNow.Add(-time.Hour),
		created.Session.ID,
	)
	require.NoError(t, err)
	cleanupAtTokenBoundary, err := repoA.Cleanup(context.Background(), auth.ProviderSessionCleanupPolicy{
		Now:              cleanupNow,
		TokenRetention:   time.Hour,
		SessionRetention: 24 * time.Hour,
		BatchSize:        10,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, cleanupAtTokenBoundary.TokenRecords)
	require.Zero(t, cleanupAtTokenBoundary.SessionRecords)

	_, err = db.Exec(
		"UPDATE provider_sessions SET updated_at = ? WHERE id = ?",
		cleanupNow.Add(-24*time.Hour),
		created.Session.ID,
	)
	require.NoError(t, err)
	cleanupAtSessionBoundary, err := repoB.Cleanup(context.Background(), auth.ProviderSessionCleanupPolicy{
		Now:              cleanupNow,
		TokenRetention:   time.Hour,
		SessionRetention: 24 * time.Hour,
		BatchSize:        10,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, cleanupAtSessionBoundary.SessionRecords)
}
