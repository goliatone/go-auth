package repository

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

const sqliteOIDCStateSchema = `
CREATE TABLE oidc_states (
	state_hash BLOB NOT NULL PRIMARY KEY,
	provider_key TEXT NOT NULL,
	nonce TEXT NOT NULL,
	verifier_version INTEGER NOT NULL,
	verifier_algorithm TEXT NOT NULL,
	verifier_key_id TEXT NOT NULL,
	verifier_nonce BLOB NOT NULL,
	verifier_ciphertext BLOB NOT NULL,
	redirect_to TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_oidc_states_expires_at ON oidc_states(expires_at);`

func TestOIDCStateStoreCrossInstanceConsumeOnceAndRedactsStorage(t *testing.T) {
	db := openOIDCStateTestDB(t)
	cipher := newStateTestCipher(t)
	storeA, err := NewOIDCStateStore(db, cipher)
	require.NoError(t, err)
	storeB, err := NewOIDCStateStore(db, cipher)
	require.NoError(t, err)

	record := oidc.StateRecord{
		State:        "browser-state-secret",
		Nonce:        "nonce-1",
		CodeVerifier: "pkce-verifier-secret",
		ProviderKey:  "provider",
		RedirectTo:   "/after",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}
	require.NoError(t, storeA.Save(context.Background(), record))

	var stateHash, ciphertext []byte
	require.NoError(t, db.QueryRow("SELECT state_hash, verifier_ciphertext FROM oidc_states").Scan(&stateHash, &ciphertext))
	require.NotEqual(t, []byte(record.State), stateHash)
	require.NotContains(t, string(ciphertext), record.CodeVerifier)

	var wg sync.WaitGroup
	wg.Add(2)
	results := make(chan oidc.StateRecord, 2)
	errs := make(chan error, 2)
	for _, store := range []*OIDCStateStore{storeA, storeB} {
		go func(candidate *OIDCStateStore) {
			defer wg.Done()
			result, consumeErr := candidate.Consume(context.Background(), record.State)
			results <- result
			errs <- consumeErr
		}(store)
	}
	wg.Wait()
	close(results)
	close(errs)

	successes := 0
	for consumeErr := range errs {
		if consumeErr == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	for result := range results {
		if result.CodeVerifier != "" {
			require.Equal(t, record.CodeVerifier, result.CodeVerifier)
			require.Equal(t, record.Nonce, result.Nonce)
		}
	}

	_, err = storeA.Consume(context.Background(), record.State)
	require.ErrorIs(t, err, oidc.ErrInvalidState)
}

func TestOIDCStateStoreExpiryAndCleanup(t *testing.T) {
	db := openOIDCStateTestDB(t)
	store, err := NewOIDCStateStore(db, newStateTestCipher(t))
	require.NoError(t, err)

	expired := oidc.StateRecord{
		State: "expired-state", Nonce: "nonce", CodeVerifier: "verifier",
		ProviderKey: "provider", ExpiresAt: time.Now().UTC().Add(-time.Minute),
	}
	require.NoError(t, store.Save(context.Background(), expired))
	_, err = store.Consume(context.Background(), expired.State)
	require.ErrorIs(t, err, oidc.ErrInvalidState)

	for _, state := range []string{"cleanup-1", "cleanup-2"} {
		require.NoError(t, store.Save(context.Background(), oidc.StateRecord{
			State: state, Nonce: "nonce", CodeVerifier: "verifier",
			ProviderKey: "provider", ExpiresAt: time.Now().UTC().Add(-time.Minute),
		}))
	}
	removed, err := store.CleanupExpired(context.Background(), time.Now().UTC(), 1)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)
	removed, err = store.CleanupExpired(context.Background(), time.Now().UTC(), 10)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)
}

func openOIDCStateTestDB(t *testing.T) *bun.DB {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", "file:"+t.TempDir()+"/oidc-state.db?_busy_timeout=5000&_journal_mode=WAL")
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	db := bun.NewDB(sqlDB, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(sqliteOIDCStateSchema)
	require.NoError(t, err)
	return db
}

type stateTestCipher struct {
	aead cipher.AEAD
}

func newStateTestCipher(t *testing.T) stateTestCipher {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 32))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return stateTestCipher{aead: aead}
}

func (c stateTestCipher) Seal(_ context.Context, plaintext, associatedData []byte) (auth.TokenEnvelope, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return auth.TokenEnvelope{}, err
	}
	return auth.TokenEnvelope{
		Version: 1, Algorithm: "AES-256-GCM", KeyID: "test",
		Nonce: nonce, Ciphertext: c.aead.Seal(nil, nonce, plaintext, associatedData),
	}, nil
}

func (c stateTestCipher) Open(_ context.Context, envelope auth.TokenEnvelope, associatedData []byte) ([]byte, error) {
	if envelope.KeyID != "test" {
		return nil, errors.New("unknown key")
	}
	return c.aead.Open(nil, envelope.Nonce, envelope.Ciphertext, associatedData)
}
