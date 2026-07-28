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
		"20260727130000_provider_session_lifecycle_fences.up.sql",
		"20260727140000_lifecycle_operation_ledger.up.sql",
		"20260727150000_provider_remote_revocation_queue.up.sql",
		"20260727160000_provider_session_reason_fingerprints.up.sql",
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

	// Lifecycle admission and invalidation share the same Postgres fence. A
	// racing create either commits first and is returned/revoked, or observes
	// the suspension and is denied.
	initialLifecycle, err := managerA.CreateProviderSession(
		context.Background(),
		managerTestPrincipal(t),
		managerTestTokens(t),
	)
	require.NoError(t, err)
	startLifecycleRace := make(chan struct{})
	createResult := make(chan struct {
		creation auth.ProviderSessionCreation
		err      error
	}, 1)
	lifecycleResult := make(chan struct {
		revoked []auth.ProviderSession
		err     error
	}, 1)
	lifecycleAt := time.Now().UTC()
	go func() {
		<-startLifecycleRace
		creation, createErr := managerB.CreateProviderSession(
			context.Background(),
			managerTestPrincipal(t),
			managerTestTokens(t),
		)
		createResult <- struct {
			creation auth.ProviderSessionCreation
			err      error
		}{creation: creation, err: createErr}
	}()
	go func() {
		<-startLifecycleRace
		_, revoked, lifecycleErr := repoA.AdvanceProviderSessionLifecycle(
			context.Background(),
			auth.ProviderSessionLifecycleTransition{
				ApplicationSubject: "user-1",
				BlockedState:       auth.ProviderSessionLifecycleSuspended,
				EventObservedAt:    lifecycleAt,
				Reason:             "account suspended",
			},
		)
		lifecycleResult <- struct {
			revoked []auth.ProviderSession
			err     error
		}{revoked: revoked, err: lifecycleErr}
	}()
	close(startLifecycleRace)
	createdDuringSuspend := <-createResult
	suspended := <-lifecycleResult
	require.NoError(t, suspended.err)
	require.Contains(t, providerSessionIDs(suspended.revoked), initialLifecycle.Session.ID)
	if createdDuringSuspend.err == nil {
		require.Contains(t, providerSessionIDs(suspended.revoked), createdDuringSuspend.creation.Session.ID)
		_, _, resolveErr := managerB.ResolveProviderSession(
			context.Background(),
			createdDuringSuspend.creation.Handle,
			binding,
		)
		require.ErrorIs(t, resolveErr, auth.ErrProviderSessionRevoked)
	} else {
		require.ErrorIs(t, createdDuringSuspend.err, auth.ErrProviderSessionConflict)
	}
	_, _, err = repoB.AdvanceProviderSessionLifecycle(
		context.Background(),
		auth.ProviderSessionLifecycleTransition{
			ApplicationSubject: "user-1",
			BlockedState:       auth.ProviderSessionLifecycleActive,
			EventObservedAt:    lifecycleAt.Add(time.Second),
			Reason:             "authoritative activation",
		},
	)
	require.NoError(t, err)

	// Independent operation stores serialize claim and compare-and-swap
	// advancement through the durable ledger.
	operationStoreA, err := authrepo.NewLifecycleOperationRepository(db)
	require.NoError(t, err)
	operationStoreB, err := authrepo.NewLifecycleOperationRepository(db)
	require.NoError(t, err)
	operationClaim := auth.LifecycleOperationClaim{
		OperationID: "postgres-operation",
		Fingerprint: "sha256:postgres-operation",
		Action:      auth.ProviderActionSuspend,
	}
	startOperationRace := make(chan struct{})
	operationClaims := make(chan struct {
		record      auth.LifecycleOperationRecord
		disposition auth.LifecycleOperationClaimDisposition
		err         error
	}, 2)
	for _, store := range []auth.LifecycleOperationStore{operationStoreA, operationStoreB} {
		go func(store auth.LifecycleOperationStore) {
			<-startOperationRace
			record, disposition, claimErr := store.Claim(context.Background(), operationClaim)
			operationClaims <- struct {
				record      auth.LifecycleOperationRecord
				disposition auth.LifecycleOperationClaimDisposition
				err         error
			}{record: record, disposition: disposition, err: claimErr}
		}(store)
	}
	close(startOperationRace)
	firstClaim := <-operationClaims
	secondClaim := <-operationClaims
	require.NoError(t, firstClaim.err)
	require.NoError(t, secondClaim.err)
	require.ElementsMatch(
		t,
		[]auth.LifecycleOperationClaimDisposition{
			auth.LifecycleOperationClaimed,
			auth.LifecycleOperationExisting,
		},
		[]auth.LifecycleOperationClaimDisposition{
			firstClaim.disposition,
			secondClaim.disposition,
		},
	)

	permitCalls := 0
	permitExecutor := &postgresPermitExecutor{calls: &permitCalls}
	permitOperation := auth.AuthorizedOperationContext{
		OperationID: "postgres-permit-operation",
		Action:      auth.ProviderActionInvite,
		Permission:  "identity.invite",
		Actor:       auth.ActorRef{ID: "admin-1", Type: "user"},
		Target: auth.ProviderOperationTarget{
			Provider: "oidc", Subject: "invitee@example.test",
		},
		Reason: "approved invitation", Environment: "test",
		RequestID: "postgres-permit-request", AuthorizedAt: time.Now().UTC(),
	}
	permitCoordinator, err := auth.NewLifecycleCoordinator(auth.LifecycleCoordinatorConfig{
		Freshness: auth.LifecycleFreshnessInvalidatorFunc(
			func(context.Context, auth.LifecycleFreshnessRequest) error { return nil },
		),
		OperationStore: operationStoreA,
		RequireDurable: true,
		RequirePermits: true,
	})
	require.NoError(t, err)
	permitRequest := auth.LifecycleCoordinationRequest{
		Operation: permitOperation,
		Remote:    permitExecutor,
	}
	permitResult, err := permitCoordinator.Coordinate(context.Background(), permitRequest)
	require.NoError(t, err)
	require.Equal(t, auth.ProviderOperationSucceeded, permitResult.Remote.Status)
	require.Equal(t, 1, permitCalls)
	_, err = permitCoordinator.Coordinate(context.Background(), permitRequest)
	require.NoError(t, err)
	require.Equal(t, 1, permitCalls)

	pendingRecord, _, err := operationStoreA.Claim(
		context.Background(),
		auth.LifecycleOperationClaim{
			OperationID: "postgres-pending-operation",
			Fingerprint: "sha256:postgres-pending",
			Action:      auth.ProviderActionSuspend,
		},
	)
	require.NoError(t, err)
	pendingRecord.RemotePhase = auth.LifecyclePhasePendingReconcile
	pendingRecord, err = operationStoreA.Advance(
		context.Background(),
		pendingRecord.Revision,
		pendingRecord,
	)
	require.NoError(t, err)
	pendingClaims := make(chan int, 2)
	pendingAt := time.Now().UTC()
	for index, store := range []auth.LifecycleOperationStore{operationStoreA, operationStoreB} {
		go func(worker int, store auth.LifecycleOperationStore) {
			claims, claimErr := store.ClaimPending(
				context.Background(),
				auth.LifecycleOperationPendingPolicy{
					Now: pendingAt, LeaseOwner: fmt.Sprintf("reconciler-%d", worker),
					Lease: 30 * time.Second, Limit: 10,
				},
			)
			if claimErr != nil {
				pendingClaims <- -1
				return
			}
			pendingClaims <- len(claims)
		}(index, store)
	}
	require.Equal(t, 1, (<-pendingClaims)+(<-pendingClaims))

	// Remote retry claims are also single-owner across repository instances.
	revocationSession, err := managerA.CreateProviderSession(
		context.Background(),
		managerTestPrincipal(t),
		managerTestTokens(t),
	)
	require.NoError(t, err)
	_, changed, err = repoA.Revoke(
		context.Background(),
		revocationSession.Session.ID,
		"logout",
	)
	require.NoError(t, err)
	require.True(t, changed)
	require.NoError(t, repoA.UpdateRemoteRevocation(
		context.Background(),
		revocationSession.Session.ID,
		auth.ProviderRemoteRevocationOutcome{
			Status: auth.ProviderRemoteRevocationPending, Retryable: true,
		},
	))
	startRevocationRace := make(chan struct{})
	revocationClaims := make(chan struct {
		claims []auth.ProviderRemoteRevocationClaim
		err    error
	}, 2)
	for index, repository := range []*authrepo.ProviderSessionRepository{repoA, repoB} {
		go func(worker int, repository *authrepo.ProviderSessionRepository) {
			<-startRevocationRace
			claims, claimErr := repository.ClaimRemoteRevocations(
				context.Background(),
				auth.ProviderRemoteRevocationClaimPolicy{
					Now:       time.Now().UTC().Add(time.Minute),
					WorkerID:  fmt.Sprintf("postgres-worker-%d", worker),
					Lease:     30 * time.Second,
					BatchSize: 10,
				},
			)
			revocationClaims <- struct {
				claims []auth.ProviderRemoteRevocationClaim
				err    error
			}{claims: claims, err: claimErr}
		}(index, repository)
	}
	close(startRevocationRace)
	claimedA := <-revocationClaims
	claimedB := <-revocationClaims
	require.NoError(t, claimedA.err)
	require.NoError(t, claimedB.err)
	require.Equal(t, 1, len(claimedA.claims)+len(claimedB.claims))
}

type postgresPermitExecutor struct {
	calls *int
}

func (*postgresPermitExecutor) ExecuteProviderOperation(
	context.Context,
	auth.AuthorizedOperationContext,
) (auth.ProviderOperationOutcome, error) {
	return auth.ProviderOperationOutcome{}, auth.ErrProviderOperationUnauthorized
}

func (e *postgresPermitExecutor) ExecuteCoordinatedProviderOperation(
	ctx context.Context,
	operation auth.AuthorizedOperationContext,
	permit auth.LifecycleExecutionPermit,
) (auth.ProviderOperationOutcome, error) {
	if err := permit.ConsumeForHardenedMutation(ctx, operation); err != nil {
		return auth.ProviderOperationOutcome{Status: auth.ProviderOperationFailed}, err
	}
	(*e.calls)++
	return auth.ProviderOperationOutcome{Status: auth.ProviderOperationSucceeded}, nil
}

func providerSessionIDs(sessions []auth.ProviderSession) []string {
	ids := make([]string, 0, len(sessions))
	for _, session := range sessions {
		ids = append(ids, session.ID)
	}
	return ids
}
