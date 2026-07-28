package auth_test

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	authrepo "github.com/goliatone/go-auth/repository"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

func newTestProviderSessionManager(
	config auth.ProviderSessionManagerConfig,
) (*auth.ProviderSessionManager, error) {
	if config.Deployment == "" {
		config.Deployment = auth.ProviderSessionDeploymentTest
	}
	return auth.NewProviderSessionManager(config)
}

func TestProviderSessionManagerOIDCHandoffCreatesAtomicEncryptedSession(t *testing.T) {
	db, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo,
		Cipher:     tokenCipher,
		Binding: auth.ProviderSessionBinding{
			Host: "app.example.com", ApplicationID: "app", Environment: "test",
			Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
		},
		IdleLifetime: time.Hour,
		MaxLifetime:  8 * time.Hour,
	})
	require.NoError(t, err)

	principal := managerTestPrincipal(t)
	tokens := managerTestTokens(t)
	handoff, err := (oidc.SessionCreatorHandoff{Creator: manager}).CreateProviderSession(context.Background(), principal, tokens)
	require.NoError(t, err)
	require.False(t, handoff.HostSession().IsZero())
	require.NotEmpty(t, handoff.LocalSessionID())

	var lookupHash, ciphertext []byte
	require.NoError(t, db.QueryRow(`
		SELECT s.lookup_hash, t.ciphertext
		FROM provider_sessions s
		JOIN provider_session_tokens t ON t.session_id = s.id`).Scan(&lookupHash, &ciphertext))
	require.Len(t, lookupHash, 32)
	require.NotContains(t, string(ciphertext), "access-token-secret")
	require.NotContains(t, string(ciphertext), "refresh-token-secret")
	require.NotEqual(t, handoff.HostSession().Reveal(), string(lookupHash))
}

func TestProviderSessionManagerLocalInvalidationDoesNotInvokeRemoteHook(t *testing.T) {
	_, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	hook := &countingProviderRevocationHook{}
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour, RevocationHook: hook,
	})
	require.NoError(t, err)
	created, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)

	require.NoError(t, manager.InvalidateProviderSession(context.Background(), created.Session.ID, "suspend"))
	require.Zero(t, hook.calls.Load())
	_, _, err = manager.ResolveProviderSession(context.Background(), created.Handle, binding)
	require.ErrorIs(t, err, auth.ErrProviderSessionRevoked)
}

func TestProviderSessionManagerSealFailureLeavesNoPartialSession(t *testing.T) {
	db, repo := openManagerIntegrationRepository(t)
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo,
		Cipher:     failingManagerCipher{},
		Binding: auth.ProviderSessionBinding{
			Host: "app.example.com", ApplicationID: "app", Environment: "test",
			Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
		},
		IdleLifetime: time.Hour,
		MaxLifetime:  8 * time.Hour,
	})
	require.NoError(t, err)
	_, err = manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.ErrorIs(t, err, auth.ErrProviderTokenCipher)
	var count int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM provider_sessions").Scan(&count))
	require.Zero(t, count)
}

func TestProviderSessionManagerReencryptsWithActiveKey(t *testing.T) {
	db, repo := openManagerIntegrationRepository(t)
	oldKey, err := auth.NewTokenEncryptionKey("old", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("old", oldKey)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	created, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)

	newKey, err := auth.NewTokenEncryptionKey("new", []byte("11111111111111111111111111111111"), false)
	require.NoError(t, err)
	require.NoError(t, keys.Rotate(newKey))
	require.NoError(t, keys.Retire("old"))
	updated, err := manager.ReencryptProviderSession(context.Background(), created.Handle, binding)
	require.NoError(t, err)
	require.EqualValues(t, 2, updated.TokenRevision)

	var keyID string
	var revision int64
	require.NoError(t, db.QueryRow(
		"SELECT key_id, token_revision FROM provider_session_tokens WHERE session_id = ?",
		created.Session.ID,
	).Scan(&keyID, &revision))
	require.Equal(t, "new", keyID)
	require.EqualValues(t, 2, revision)
	_, _, err = manager.ResolveProviderSession(context.Background(), created.Handle, binding)
	require.NoError(t, err)
}

func TestProviderSessionManagerRotatesOpaqueHandle(t *testing.T) {
	_, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	created, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)
	next, _, err := manager.RotateProviderSessionHandle(context.Background(), created.Handle, binding)
	require.NoError(t, err)
	require.NotEqual(t, created.Handle.Reveal(), next.Reveal())

	_, _, err = manager.ResolveProviderSession(context.Background(), created.Handle, binding)
	require.ErrorIs(t, err, auth.ErrProviderSessionNotFound)
	_, _, err = manager.ResolveProviderSession(context.Background(), next, binding)
	require.NoError(t, err)
}

func TestProviderSessionManagerCrossReplicaRefreshConverges(t *testing.T) {
	db, repoA := openManagerIntegrationRepository(t)
	repoB, err := authrepo.NewProviderSessionRepository(db)
	require.NoError(t, err)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	refresher := &blockingProviderRefresher{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
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

	type refreshResult struct {
		session auth.ProviderSession
		err     error
	}
	results := make(chan refreshResult, 2)
	go func() {
		session, refreshErr := managerA.RefreshProviderSession(context.Background(), created.Handle, binding)
		results <- refreshResult{session: session, err: refreshErr}
	}()
	<-refresher.started
	go func() {
		session, refreshErr := managerB.RefreshProviderSession(context.Background(), created.Handle, binding)
		results <- refreshResult{session: session, err: refreshErr}
	}()
	time.Sleep(30 * time.Millisecond)
	close(refresher.release)

	for range 2 {
		result := <-results
		require.NoError(t, result.err)
		require.EqualValues(t, 2, result.session.TokenRevision)
	}
	require.EqualValues(t, 1, refresher.calls.Load())
}

func TestProviderSessionManagerAmbiguousRefreshBecomesUnusable(t *testing.T) {
	db, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	refresher := &failingProviderRefresher{}
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding, Refresher: refresher,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	created, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)

	_, err = manager.RefreshProviderSession(context.Background(), created.Handle, binding)
	require.ErrorIs(t, err, auth.ErrProviderRefreshAmbiguous)
	_, _, err = manager.ResolveProviderSession(context.Background(), created.Handle, binding)
	require.ErrorIs(t, err, auth.ErrProviderSessionUncertain)
	_, err = manager.RefreshProviderSession(context.Background(), created.Handle, binding)
	require.ErrorIs(t, err, auth.ErrProviderSessionUncertain)
	require.EqualValues(t, 1, refresher.calls.Load())

	var status string
	require.NoError(t, db.QueryRow("SELECT status FROM provider_sessions WHERE id = ?", created.Session.ID).Scan(&status))
	require.Equal(t, string(auth.ProviderSessionUncertain), status)
}

func TestProviderSessionManagerAuthoritativeReconciliationCommitsTokens(t *testing.T) {
	_, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	reconciledTokens, err := auth.NewProviderTokenSet(auth.ProviderTokenSetInput{
		AccessToken: auth.NewSecret("reconciled-access"), RefreshToken: auth.NewSecret("reconciled-refresh"),
		TokenType: "Bearer", AcquiredAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		Refresher: &failingProviderRefresher{},
		Reconciler: fixedProviderReconciler{
			result: auth.ProviderRefreshReconcileResult{
				Status: auth.ProviderRefreshReconciledTokens, Tokens: reconciledTokens,
			},
		},
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	created, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)
	session, err := manager.RefreshProviderSession(context.Background(), created.Handle, binding)
	require.NoError(t, err)
	require.EqualValues(t, 2, session.TokenRevision)
	require.Equal(t, auth.ProviderSessionAvailable, session.Status)
}

func TestProviderSessionManagerRevokesLocallyBeforeProviderFailure(t *testing.T) {
	db, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	sink := &captureProviderActivitySink{}
	hook := &assertLocalFirstRevocationHook{db: db}
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		RevocationHook: hook, ActivitySink: sink,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	created, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)
	hook.sessionID = created.Session.ID

	err = manager.RevokeCurrentProviderSession(context.Background(), created.Handle, binding, "logout")
	require.Error(t, err)
	_, _, resolveErr := manager.ResolveProviderSession(context.Background(), created.Handle, binding)
	require.ErrorIs(t, resolveErr, auth.ErrProviderSessionRevoked)
	require.EqualValues(t, 1, hook.calls.Load())
	require.NoError(t, manager.RevokeCurrentProviderSession(context.Background(), created.Handle, binding, "duplicate logout"))
	require.EqualValues(t, 1, hook.calls.Load())

	var status, remoteStatus string
	require.NoError(t, db.QueryRow(
		"SELECT status, remote_revocation_status FROM provider_sessions WHERE id = ?",
		created.Session.ID,
	).Scan(&status, &remoteStatus))
	require.Equal(t, string(auth.ProviderSessionRevoked), status)
	require.Equal(t, string(auth.ProviderRemoteRevocationPending), remoteStatus)
	require.NotEmpty(t, sink.events)
	for _, event := range sink.events {
		require.NotContains(t, event.Metadata, "access_token")
		require.NotContains(t, event.Metadata, "refresh_token")
	}
}

func TestProviderSessionManagerRetriesRetainedRemoteWorkAfterRestart(t *testing.T) {
	db, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	hook := &retryThenSucceedRevocationHook{}
	firstManager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		RevocationHook: hook, IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	created, err := firstManager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)
	err = firstManager.RevokeProviderSession(context.Background(), created.Session.ID, "administrative revoke")
	require.Error(t, err)
	require.EqualValues(t, 1, hook.calls.Load())

	var tokenRows int
	require.NoError(t, db.QueryRow(
		"SELECT COUNT(*) FROM provider_session_tokens WHERE session_id = ?",
		created.Session.ID,
	).Scan(&tokenRows))
	require.Equal(t, 1, tokenRows)

	restartedManager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		RevocationHook: hook, IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	retry, err := restartedManager.RetryRemoteRevocations(context.Background(), auth.ProviderRemoteRevocationClaimPolicy{
		Now:         time.Now().UTC().Add(time.Second),
		WorkerID:    "retry-worker",
		Lease:       30 * time.Second,
		BatchSize:   10,
		MaxAttempts: 3,
	})
	require.NoError(t, err)
	require.Equal(t, 1, retry.Claimed)
	require.Equal(t, 1, retry.Succeeded)
	require.EqualValues(t, 2, hook.calls.Load())

	resolved, err := repo.Load(context.Background(), created.Session.ID)
	require.ErrorIs(t, err, auth.ErrProviderSessionUnavailable)
	require.Empty(t, resolved.Tokens.Ciphertext)
	var status string
	var retryable bool
	require.NoError(t, db.QueryRow(
		"SELECT status, remote_revocation_retryable FROM provider_sessions WHERE id = ?",
		created.Session.ID,
	).Scan(&status, &retryable))
	require.Equal(t, string(auth.ProviderSessionRevoked), status)
	require.False(t, retryable)
	require.NoError(t, db.QueryRow(
		"SELECT COUNT(*) FROM provider_session_tokens WHERE session_id = ?",
		created.Session.ID,
	).Scan(&tokenRows))
	require.Zero(t, tokenRows)
}

func TestProviderSessionManagerRevokesAllUserSessions(t *testing.T) {
	_, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	first, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)
	second, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerTestTokens(t))
	require.NoError(t, err)
	require.NoError(t, manager.RevokeUserProviderSessions(context.Background(), "user-1", "account suspended"))
	for _, handle := range []auth.Secret{first.Handle, second.Handle} {
		_, _, resolveErr := manager.ResolveProviderSession(context.Background(), handle, binding)
		require.ErrorIs(t, resolveErr, auth.ErrProviderSessionRevoked)
	}
}

func TestSerializedLifecycleOrderingRevokesAndQueuesAcrossClockSkew(t *testing.T) {
	_, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	future := time.Now().UTC().Add(24 * time.Hour)
	_, _, err = manager.ApplyProviderSessionLifecycle(
		context.Background(),
		auth.ProviderSessionLifecycleTransition{
			ApplicationSubject: "user-1",
			BlockedState:       auth.ProviderSessionLifecycleActive,
			EventObservedAt:    future,
			Ordering:           auth.ProviderSessionLifecycleObservedOrder,
			Reason:             "future-dated activation",
		},
	)
	require.NoError(t, err)
	created, err := manager.CreateProviderSession(
		context.Background(),
		managerTestPrincipal(t),
		managerTestTokens(t),
	)
	require.NoError(t, err)

	behind := future.Add(-48 * time.Hour)
	coordinator, err := auth.NewLifecycleCoordinator(auth.LifecycleCoordinatorConfig{
		LocalInvalidator:     manager,
		LifecycleInvalidator: manager,
		Freshness: auth.LifecycleFreshnessInvalidatorFunc(
			func(context.Context, auth.LifecycleFreshnessRequest) error { return nil },
		),
		OperationStore: auth.NewInMemoryLifecycleOperationStore(func() time.Time {
			return behind
		}),
		Clock: func() time.Time { return behind },
	})
	require.NoError(t, err)
	operation := auth.AuthorizedOperationContext{
		OperationID: "clock-skew-suspend",
		Action:      auth.ProviderActionSuspend,
		Permission:  "identity.manage",
		Actor:       auth.ActorRef{ID: "admin-1", Type: "user"},
		Target: auth.ProviderOperationTarget{
			Provider: "oidc", ApplicationSubject: "user-1", Subject: "provider-user-1",
		},
		Reason: "security suspend", Environment: "test", RequestID: "request-1",
		AuthorizedAt: time.Now().UTC(),
	}
	_, err = coordinator.Coordinate(context.Background(), auth.LifecycleCoordinationRequest{
		Operation: operation,
		Remote: auth.ProviderOperationExecutorFunc(
			func(context.Context, auth.AuthorizedOperationContext) (auth.ProviderOperationOutcome, error) {
				return auth.ProviderOperationOutcome{Status: auth.ProviderOperationSucceeded}, nil
			},
		),
	})
	require.NoError(t, err)
	_, _, err = manager.ResolveProviderSession(context.Background(), created.Handle, binding)
	require.ErrorIs(t, err, auth.ErrProviderSessionRevoked)

	claims, err := repo.ClaimRemoteRevocations(
		context.Background(),
		auth.ProviderRemoteRevocationClaimPolicy{
			Now: time.Now().UTC().Add(time.Minute), WorkerID: "lifecycle-revoker",
			Lease: 30 * time.Second, BatchSize: 10, MaxAttempts: 3,
		},
	)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	require.Equal(t, created.Session.ID, claims[0].Session.ID)
	require.Equal(t, auth.ProviderRemoteRevocationPending, claims[0].Session.RemoteRevocation.Status)
	require.True(t, claims[0].Session.RemoteRevocation.Retryable)
	require.False(t, claims[0].Session.RemoteWorkExpiresAt.IsZero())
}

func TestProviderSessionManagerAccessTokenRequiresCurrentSessionTargetAndPolicy(t *testing.T) {
	_, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	capability, err := auth.NewTokenTargetCapability()
	require.NoError(t, err)
	registry, err := auth.NewTokenTargetRegistry(auth.TokenTarget{
		Name: "business", Provider: "oidc", Issuer: binding.Issuer, ClientID: binding.ClientID,
		Audience: "business-api", RequiredScopes: []string{"read"}, TelemetryName: "business",
		RequirePolicy: true, Capability: capability,
	})
	require.NoError(t, err)
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		TargetRegistry: registry, AccessPolicy: allowTokenAccessPolicy{},
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	created, err := manager.CreateProviderSession(
		context.Background(),
		managerTestPrincipal(t),
		managerBoundAccessTokens(t, time.Now().UTC().Add(time.Hour)),
	)
	require.NoError(t, err)
	requestCtx := auth.WithProviderSessionContext(context.Background(), created.Session, created.Principal)
	token, err := manager.AccessToken(requestCtx, auth.UserTokenRequest{
		SessionHandle: created.Handle, Binding: binding, Target: "business", Capability: capability,
	})
	require.NoError(t, err)
	require.Equal(t, "bound-access-token", token.Reveal())

	wrongCapability, err := auth.NewTokenTargetCapability()
	require.NoError(t, err)
	_, err = manager.AccessToken(requestCtx, auth.UserTokenRequest{
		SessionHandle: created.Handle, Binding: binding, Target: "business", Capability: wrongCapability,
	})
	require.ErrorIs(t, err, auth.ErrProviderTokenTarget)
	_, err = manager.AccessToken(context.Background(), auth.UserTokenRequest{
		SessionHandle: created.Handle, Binding: binding, Target: "business", Capability: capability,
	})
	require.ErrorIs(t, err, auth.ErrProviderTokenPolicy)
}

func TestProviderSessionManagerAccessTokenFailsClosedWithoutRequiredPolicy(t *testing.T) {
	_, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	capability, err := auth.NewTokenTargetCapability()
	require.NoError(t, err)
	registry, err := auth.NewTokenTargetRegistry(auth.TokenTarget{
		Name: "business", Provider: "oidc", Issuer: binding.Issuer, ClientID: binding.ClientID,
		Audience: "business-api", TelemetryName: "business", RequirePolicy: true, Capability: capability,
	})
	require.NoError(t, err)
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding, TargetRegistry: registry,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	created, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), managerBoundAccessTokens(t, time.Now().UTC().Add(time.Hour)))
	require.NoError(t, err)
	requestCtx := auth.WithProviderSessionContext(context.Background(), created.Session, created.Principal)
	_, err = manager.AccessToken(requestCtx, auth.UserTokenRequest{
		SessionHandle: created.Handle, Binding: binding, Target: "business", Capability: capability,
	})
	require.ErrorIs(t, err, auth.ErrProviderTokenPolicyUnavailable)
}

func TestProviderSessionManagerAccessTokenRefreshesInternally(t *testing.T) {
	_, repo := openManagerIntegrationRepository(t)
	key, err := auth.NewTokenEncryptionKey("key-1", make([]byte, 32), false)
	require.NoError(t, err)
	keys, err := auth.NewStaticTokenKeyProvider("key-1", key)
	require.NoError(t, err)
	tokenCipher, err := auth.NewAESGCMTokenCipher(keys)
	require.NoError(t, err)
	binding := auth.ProviderSessionBinding{
		Host: "app.example.com", ApplicationID: "app", Environment: "test",
		Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
	}
	capability, err := auth.NewTokenTargetCapability()
	require.NoError(t, err)
	registry, err := auth.NewTokenTargetRegistry(auth.TokenTarget{
		Name: "business", Provider: "oidc", Issuer: binding.Issuer, ClientID: binding.ClientID,
		Audience: "business-api", RequiredScopes: []string{"read"}, TelemetryName: "business",
		Capability: capability,
	})
	require.NoError(t, err)
	refreshed := managerBoundAccessTokens(t, time.Now().UTC().Add(time.Hour))
	refresher := &fixedProviderRefresher{tokens: refreshed}
	manager, err := newTestProviderSessionManager(auth.ProviderSessionManagerConfig{
		Repository: repo, Cipher: tokenCipher, Binding: binding,
		TargetRegistry: registry, Refresher: refresher,
		IdleLifetime: time.Hour, MaxLifetime: 8 * time.Hour,
	})
	require.NoError(t, err)
	expired := managerBoundAccessTokens(t, time.Now().UTC().Add(-time.Minute))
	created, err := manager.CreateProviderSession(context.Background(), managerTestPrincipal(t), expired)
	require.NoError(t, err)
	requestCtx := auth.WithProviderSessionContext(context.Background(), created.Session, created.Principal)
	token, err := manager.AccessToken(requestCtx, auth.UserTokenRequest{
		SessionHandle: created.Handle, Binding: binding, Target: "business", Capability: capability,
	})
	require.NoError(t, err)
	require.Equal(t, "bound-access-token", token.Reveal())
	require.EqualValues(t, 1, refresher.calls.Load())
}

func openManagerIntegrationRepository(t *testing.T) (*bun.DB, *authrepo.ProviderSessionRepository) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", "file:"+t.TempDir()+"/manager.db?_fk=1")
	require.NoError(t, err)
	db := bun.NewDB(sqlDB, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close() })
	for _, name := range []string{
		"20260726100000_provider_sessions.up.sql",
		"20260726120000_provider_session_authorization_fences.up.sql",
		"20260727130000_provider_session_lifecycle_fences.up.sql",
		"20260727150000_provider_remote_revocation_queue.up.sql",
		"20260727160000_provider_session_reason_fingerprints.up.sql",
	} {
		raw, readErr := fs.ReadFile(auth.GetAuthExtrasMigrationsFS(), "data/sql/migrations/sqlite/"+name)
		require.NoError(t, readErr)
		_, execErr := db.Exec(string(raw))
		require.NoError(t, execErr)
	}
	repo, err := authrepo.NewProviderSessionRepository(db)
	require.NoError(t, err)
	return db, repo
}

func managerTestPrincipal(t *testing.T) auth.AuthenticatedPrincipal {
	t.Helper()
	principal, err := auth.NewAuthenticatedPrincipal(auth.AuthenticatedPrincipalInput{
		ApplicationSubject: "user-1", Provider: "oidc", ProviderSubject: "provider-user-1", ClientID: "client-1",
	})
	require.NoError(t, err)
	return principal
}

func managerTestTokens(t *testing.T) auth.ProviderTokenSet {
	t.Helper()
	tokens, err := auth.NewProviderTokenSet(auth.ProviderTokenSetInput{
		AccessToken:  auth.NewSecret("access-token-secret"),
		RefreshToken: auth.NewSecret("refresh-token-secret"),
		TokenType:    "Bearer",
		AcquiredAt:   time.Now().UTC(),
	})
	require.NoError(t, err)
	return tokens
}

func managerBoundAccessTokens(t *testing.T, expiresAt time.Time) auth.ProviderTokenSet {
	t.Helper()
	accessContext := &auth.ValidatedTokenContext{
		Issuer: "https://issuer.example.com", Subject: "provider-user-1",
		Audiences: []string{"business-api"}, ClientID: "client-1", ExpiresAt: expiresAt,
	}
	tokens, err := auth.NewProviderTokenSet(auth.ProviderTokenSetInput{
		AccessToken: auth.NewSecret("bound-access-token"), RefreshToken: auth.NewSecret("bound-refresh-token"),
		TokenType: "Bearer", Scopes: []string{"read"}, AcquiredAt: time.Now().UTC(),
		AccessExpiresAt: expiresAt, AccessContext: accessContext,
	})
	require.NoError(t, err)
	return tokens
}

type failingManagerCipher struct{}

func (failingManagerCipher) Seal(context.Context, []byte, []byte) (auth.TokenEnvelope, error) {
	return auth.TokenEnvelope{}, errors.New("injected seal failure")
}

func (failingManagerCipher) Open(context.Context, auth.TokenEnvelope, []byte) ([]byte, error) {
	return nil, errors.New("injected open failure")
}

type blockingProviderRefresher struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int64
}

func (r *blockingProviderRefresher) RefreshProviderTokens(context.Context, auth.ProviderRefreshRequest) (auth.ProviderRefreshResult, error) {
	r.calls.Add(1)
	r.once.Do(func() { close(r.started) })
	<-r.release
	tokens, err := auth.NewProviderTokenSet(auth.ProviderTokenSetInput{
		AccessToken:  auth.NewSecret("new-access-token"),
		RefreshToken: auth.NewSecret("new-refresh-token"),
		TokenType:    "Bearer",
		AcquiredAt:   time.Now().UTC(),
	})
	return auth.ProviderRefreshResult{Tokens: tokens}, err
}

type failingProviderRefresher struct {
	calls atomic.Int64
}

func (r *failingProviderRefresher) RefreshProviderTokens(context.Context, auth.ProviderRefreshRequest) (auth.ProviderRefreshResult, error) {
	r.calls.Add(1)
	return auth.ProviderRefreshResult{}, errors.New("provider response lost")
}

type fixedProviderRefresher struct {
	tokens auth.ProviderTokenSet
	calls  atomic.Int64
}

func (r *fixedProviderRefresher) RefreshProviderTokens(context.Context, auth.ProviderRefreshRequest) (auth.ProviderRefreshResult, error) {
	r.calls.Add(1)
	return auth.ProviderRefreshResult{Tokens: r.tokens}, nil
}

type fixedProviderReconciler struct {
	result auth.ProviderRefreshReconcileResult
	err    error
}

func (r fixedProviderReconciler) ReconcileProviderRefresh(context.Context, auth.ProviderRefreshReconcileRequest) (auth.ProviderRefreshReconcileResult, error) {
	return r.result, r.err
}

type assertLocalFirstRevocationHook struct {
	db        *bun.DB
	sessionID string
	calls     atomic.Int64
}

func (h *assertLocalFirstRevocationHook) RevokeProviderSession(_ context.Context, _ auth.ProviderRevocationRequest) (auth.ProviderRemoteRevocationOutcome, error) {
	h.calls.Add(1)
	var status string
	if err := h.db.QueryRow("SELECT status FROM provider_sessions WHERE id = ?", h.sessionID).Scan(&status); err != nil {
		return auth.ProviderRemoteRevocationOutcome{}, err
	}
	if status != string(auth.ProviderSessionRevoked) {
		return auth.ProviderRemoteRevocationOutcome{}, errors.New("local session still usable")
	}
	return auth.ProviderRemoteRevocationOutcome{
		Status: auth.ProviderRemoteRevocationPending, Retryable: true,
	}, errors.New("provider unavailable")
}

type countingProviderRevocationHook struct {
	calls atomic.Int32
}

type retryThenSucceedRevocationHook struct {
	calls atomic.Int32
}

func (h *retryThenSucceedRevocationHook) RevokeProviderSession(
	context.Context,
	auth.ProviderRevocationRequest,
) (auth.ProviderRemoteRevocationOutcome, error) {
	if h.calls.Add(1) == 1 {
		return auth.ProviderRemoteRevocationOutcome{
			Status: auth.ProviderRemoteRevocationPending, Retryable: true,
		}, errors.New("temporary provider outage")
	}
	return auth.ProviderRemoteRevocationOutcome{Status: auth.ProviderRemoteRevocationSucceeded}, nil
}

func (h *countingProviderRevocationHook) RevokeProviderSession(context.Context, auth.ProviderRevocationRequest) (auth.ProviderRemoteRevocationOutcome, error) {
	h.calls.Add(1)
	return auth.ProviderRemoteRevocationOutcome{Status: auth.ProviderRemoteRevocationSucceeded}, nil
}

type captureProviderActivitySink struct {
	events []auth.ActivityEvent
}

func (s *captureProviderActivitySink) Record(_ context.Context, event auth.ActivityEvent) error {
	s.events = append(s.events, event)
	return nil
}

type allowTokenAccessPolicy struct{}

func (allowTokenAccessPolicy) AuthorizeProviderToken(context.Context, auth.TokenAccessPolicyRequest) error {
	return nil
}
