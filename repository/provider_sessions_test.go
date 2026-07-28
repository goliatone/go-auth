package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"io/fs"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

func TestProviderSessionRepositoryCreateResolveTouchRotateAndRevoke(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	input := providerSessionCreateFixture(t, now, "handle-1", "user-1")

	created, err := repo.Create(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, input.Session.LocalSessionID, created.LocalSessionID)

	resolved, err := repo.Resolve(context.Background(), input.LookupHash, input.Session.Binding, time.Minute)
	require.NoError(t, err)
	require.Equal(t, input.Session.ID, resolved.Session.ID)
	require.Equal(t, input.Tokens.Ciphertext, resolved.Tokens.Ciphertext)
	require.True(t, resolved.Session.LastSeenAt.After(input.Session.LastSeenAt))
	require.False(t, resolved.Session.IdleExpiresAt.After(input.Session.MaxExpiresAt))

	wrongBinding := input.Session.Binding
	wrongBinding.Environment = "other"
	_, err = repo.Resolve(context.Background(), input.LookupHash, wrongBinding, time.Minute)
	require.ErrorIs(t, err, auth.ErrProviderSessionBinding)

	newLookup := sha256.Sum256([]byte("handle-2"))
	_, err = repo.RotateHandle(context.Background(), input.Session.ID, input.Session.TokenRevision, input.LookupHash, newLookup[:])
	require.NoError(t, err)
	_, err = repo.Resolve(context.Background(), input.LookupHash, input.Session.Binding, time.Minute)
	require.ErrorIs(t, err, auth.ErrProviderSessionNotFound)
	_, err = repo.Resolve(context.Background(), newLookup[:], input.Session.Binding, time.Minute)
	require.NoError(t, err)

	revoked, changed, err := repo.Revoke(context.Background(), input.Session.ID, "logout")
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, auth.ProviderSessionRevoked, revoked.Status)
	require.Equal(t, auth.ProviderSessionReasonLogout, revoked.RevocationReasonCode)
	require.Equal(t, auth.FingerprintProviderAuditValue("logout"), revoked.RevocationReasonFingerprint)
	var persistedReason, persistedFingerprint string
	require.NoError(t, db.QueryRow(
		"SELECT revocation_reason, revocation_reason_fingerprint FROM provider_sessions WHERE id = ?",
		input.Session.ID,
	).Scan(&persistedReason, &persistedFingerprint))
	require.Equal(t, string(auth.ProviderSessionReasonLogout), persistedReason)
	require.Equal(t, string(auth.FingerprintProviderAuditValue("logout")), persistedFingerprint)
	_, changed, err = repo.Revoke(context.Background(), input.Session.ID, "logout again")
	require.NoError(t, err)
	require.False(t, changed)
	_, err = repo.Resolve(context.Background(), newLookup[:], input.Session.Binding, time.Minute)
	require.ErrorIs(t, err, auth.ErrProviderSessionRevoked)

	var tokenRows int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM provider_session_tokens WHERE session_id = ?", input.Session.ID).Scan(&tokenRows))
	require.Equal(t, 1, tokenRows)
}

func TestProviderSessionRepositoryAtomicCreateRollsBackTokenFailure(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	_, err := db.Exec(`
		CREATE TRIGGER fail_provider_token_insert
		BEFORE INSERT ON provider_session_tokens
		WHEN NEW.key_id = 'fail'
		BEGIN
			SELECT RAISE(ABORT, 'injected token failure');
		END;`)
	require.NoError(t, err)

	input := providerSessionCreateFixture(t, time.Now().UTC(), "rollback-handle", "user-rollback")
	input.Tokens.KeyID = "fail"
	_, err = repo.Create(context.Background(), input)
	require.ErrorIs(t, err, auth.ErrProviderSessionUnavailable)

	var sessionRows int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM provider_sessions WHERE id = ?", input.Session.ID).Scan(&sessionRows))
	require.Zero(t, sessionRows)
}

func TestProviderSessionRepositoryFingerprintsLegacyRevocationReasonImmediately(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	input := providerSessionCreateFixture(t, time.Now().UTC(), "reason-handle", "reason-user")
	require.NoError(t, createProviderSession(t, repo, input))
	const rawReason = "customer alice@example.test bearer persistence-canary"

	revoked, changed, err := repo.Revoke(context.Background(), input.Session.ID, rawReason)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, auth.ProviderSessionReasonLegacyExternal, revoked.RevocationReasonCode)
	require.Equal(t, auth.FingerprintProviderAuditValue(rawReason), revoked.RevocationReasonFingerprint)

	var reasonCode, reasonFingerprint string
	require.NoError(t, db.QueryRow(
		"SELECT revocation_reason, revocation_reason_fingerprint FROM provider_sessions WHERE id = ?",
		input.Session.ID,
	).Scan(&reasonCode, &reasonFingerprint))
	require.Equal(t, string(auth.ProviderSessionReasonLegacyExternal), reasonCode)
	require.Equal(t, string(auth.FingerprintProviderAuditValue(rawReason)), reasonFingerprint)
	require.NotContains(t, reasonCode+" "+reasonFingerprint, rawReason)
}

func TestProviderSessionRepositoryNormalizesMalformedEncodedReason(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	input := providerSessionCreateFixture(t, now, "malformed-reason", "user-malformed")
	require.NoError(t, createProviderSession(t, repo, input))
	const rawSuffix = "raw-persistence-secret@example.test"
	_, changed, err := repo.Revoke(
		context.Background(),
		input.Session.ID,
		"logout|sha256:"+rawSuffix,
	)
	require.NoError(t, err)
	require.True(t, changed)

	var reasonFingerprint string
	require.NoError(t, db.QueryRow(
		"SELECT revocation_reason_fingerprint FROM provider_sessions WHERE id = ?",
		input.Session.ID,
	).Scan(&reasonFingerprint))
	require.Equal(
		t,
		string(auth.FingerprintProviderAuditValue("sha256:"+rawSuffix)),
		reasonFingerprint,
	)
	require.NotContains(t, reasonFingerprint, rawSuffix)
}

func TestProviderSessionRepositoryRevokeUserAndExpiry(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	first := providerSessionCreateFixture(t, now, "first", "shared-user")
	second := providerSessionCreateFixture(t, now, "second", "shared-user")
	require.NoError(t, createProviderSession(t, repo, first))
	require.NoError(t, createProviderSession(t, repo, second))

	revoked, err := repo.RevokeUser(context.Background(), "shared-user", "suspended")
	require.NoError(t, err)
	require.Len(t, revoked, 2)
	for _, session := range revoked {
		require.Equal(t, auth.ProviderSessionRevoked, session.Status)
	}

	expired := providerSessionCreateFixture(t, now, "expired", "expired-user")
	require.NoError(t, createProviderSession(t, repo, expired))
	_, err = db.Exec(
		"UPDATE provider_sessions SET idle_expires_at = ? WHERE id = ?",
		now.Add(-time.Minute),
		expired.Session.ID,
	)
	require.NoError(t, err)
	_, err = repo.Resolve(context.Background(), expired.LookupHash, expired.Session.Binding, time.Minute)
	require.ErrorIs(t, err, auth.ErrProviderSessionExpired)
}

func TestProviderSessionRepositoryRevokeScopeIsBoundedAndIndexedByDimensions(t *testing.T) {
	repo, _ := openProviderSessionTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	first := providerSessionCreateFixture(t, now, "scope-first", "scope-user")
	second := providerSessionCreateFixture(t, now, "scope-second", "scope-user")
	other := providerSessionCreateFixture(t, now, "scope-other", "other-user")
	other.Session.Binding.TenantID = "tenant-2"
	other.Session.Principal.TenantID = "tenant-2"
	require.NoError(t, createProviderSession(t, repo, first))
	require.NoError(t, createProviderSession(t, repo, second))
	require.NoError(t, createProviderSession(t, repo, other))

	revoked, more, err := repo.RevokeScope(context.Background(), auth.ProviderSessionInvalidationScope{
		ApplicationSubject: "scope-user", TenantID: "tenant-1",
	}, 1, "permission changed")
	require.NoError(t, err)
	require.Len(t, revoked, 1)
	require.True(t, more)

	revoked, more, err = repo.RevokeScope(context.Background(), auth.ProviderSessionInvalidationScope{
		ApplicationSubject: "scope-user", TenantID: "tenant-1",
	}, 1, "permission changed")
	require.NoError(t, err)
	require.Len(t, revoked, 1)
	require.False(t, more)

	revoked, more, err = repo.RevokeScope(context.Background(), auth.ProviderSessionInvalidationScope{
		TenantID: "tenant-2", SessionID: other.Session.ID,
	}, 10, "tenant invalidation")
	require.NoError(t, err)
	require.Len(t, revoked, 1)
	require.False(t, more)

	_, _, err = repo.RevokeScope(context.Background(), auth.ProviderSessionInvalidationScope{}, 10, "invalid")
	require.ErrorIs(t, err, auth.ErrProviderSessionInvalid)
}

func TestProviderSessionRepositoryAuthorizationFenceRejectsLateStaleSession(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)

	revoked, more, err := repo.RevokeScope(context.Background(), auth.ProviderSessionInvalidationScope{
		ApplicationSubject:          "fenced-user",
		TenantID:                    "tenant-1",
		PermissionVersion:           "v2",
		PermissionVersionObservedAt: now,
	}, 10, "authorization state changed")
	require.NoError(t, err)
	require.Empty(t, revoked)
	require.False(t, more)

	stale := providerSessionCreateFixture(t, now, "stale-after-fence", "fenced-user")
	_, err = repo.Create(context.Background(), stale)
	require.ErrorIs(t, err, auth.ErrProviderSessionConflict)

	current := providerSessionCreateFixture(t, now, "current-after-fence", "fenced-user")
	current.Session.Principal.PermissionVersion = "v2"
	created, err := repo.Create(context.Background(), current)
	require.NoError(t, err)
	require.Equal(t, current.Session.ID, created.ID)

	_, _, err = repo.RevokeScope(context.Background(), auth.ProviderSessionInvalidationScope{
		ApplicationSubject:          "fenced-user",
		TenantID:                    "tenant-1",
		PermissionVersion:           "v3",
		PermissionVersionObservedAt: now.Add(2 * time.Minute),
	}, 10, "newer authorization state")
	require.NoError(t, err)
	_, _, err = repo.RevokeScope(context.Background(), auth.ProviderSessionInvalidationScope{
		ApplicationSubject:          "fenced-user",
		TenantID:                    "tenant-1",
		PermissionVersion:           "v2",
		PermissionVersionObservedAt: now.Add(time.Minute),
	}, 10, "out-of-order older authorization state")
	require.NoError(t, err)

	outOfOrderStale := providerSessionCreateFixture(t, now, "stale-after-newer-fence", "fenced-user")
	outOfOrderStale.Session.Principal.PermissionVersion = "v2"
	_, err = repo.Create(context.Background(), outOfOrderStale)
	require.ErrorIs(t, err, auth.ErrProviderSessionConflict)

	latest := providerSessionCreateFixture(t, now, "latest-after-newer-fence", "fenced-user")
	latest.Session.Principal.PermissionVersion = "v3"
	_, err = repo.Create(context.Background(), latest)
	require.NoError(t, err)

	_, _, err = repo.RevokeScope(context.Background(), auth.ProviderSessionInvalidationScope{
		ApplicationSubject:          "fenced-user",
		PermissionVersion:           "v4",
		PermissionVersionObservedAt: now.Add(3 * time.Minute),
	}, 10, "newer user-wide authorization state")
	require.NoError(t, err)

	staleAcrossTenants := providerSessionCreateFixture(t, now, "stale-after-user-fence", "fenced-user")
	staleAcrossTenants.Session.Principal.PermissionVersion = "v3"
	_, err = repo.Create(context.Background(), staleAcrossTenants)
	require.ErrorIs(t, err, auth.ErrProviderSessionConflict)

	currentAcrossTenants := providerSessionCreateFixture(t, now, "current-after-user-fence", "fenced-user")
	currentAcrossTenants.Session.Principal.PermissionVersion = "v4"
	_, err = repo.Create(context.Background(), currentAcrossTenants)
	require.NoError(t, err)

	var tenantRequiredVersion string
	require.NoError(t, db.QueryRow(`
		SELECT required_permission_version
		FROM provider_session_authorization_fences
		WHERE application_subject = ? AND tenant_id = ?`,
		"fenced-user", "tenant-1",
	).Scan(&tenantRequiredVersion))
	require.Equal(t, "v3", tenantRequiredVersion)

	var userRequiredVersion string
	require.NoError(t, db.QueryRow(`
		SELECT required_permission_version
		FROM provider_session_authorization_fences
		WHERE application_subject = ? AND tenant_id = ''`,
		"fenced-user",
	).Scan(&userRequiredVersion))
	require.Equal(t, "v4", userRequiredVersion)
}

func TestProviderSessionRepositoryReencryptionUsesRevisionFence(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	input := providerSessionCreateFixture(t, time.Now().UTC(), "reencrypt", "user-reencrypt")
	require.NoError(t, createProviderSession(t, repo, input))

	next := auth.TokenEnvelope{
		Version: 1, Algorithm: "AES-256-GCM", KeyID: "key-2",
		Nonce: []byte("abcdefghijkl"), Ciphertext: []byte("new-sealed-tokens"),
	}
	updated, err := repo.ReplaceCiphertext(context.Background(), input.Session.ID, 1, next)
	require.NoError(t, err)
	require.EqualValues(t, 2, updated.TokenRevision)

	stale := auth.TokenEnvelope{
		Version: 1, Algorithm: "AES-256-GCM", KeyID: "stale",
		Nonce: []byte("abcdefghijkl"), Ciphertext: []byte("stale-sealed-tokens"),
	}
	_, err = repo.ReplaceCiphertext(context.Background(), input.Session.ID, 1, stale)
	require.ErrorIs(t, err, auth.ErrProviderSessionConflict)

	var keyID string
	var revision int64
	require.NoError(t, db.QueryRow(
		"SELECT key_id, token_revision FROM provider_session_tokens WHERE session_id = ?",
		input.Session.ID,
	).Scan(&keyID, &revision))
	require.Equal(t, "key-2", keyID)
	require.EqualValues(t, 2, revision)
}

func TestProviderSessionRepositoryAbandonedRefreshLeaseBecomesUncertain(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	input := providerSessionCreateFixture(t, time.Now().UTC(), "lease", "user-lease")
	require.NoError(t, createProviderSession(t, repo, input))
	claim, err := repo.ClaimRefresh(context.Background(), input.Session.ID, 1, "attempt-1", 5*time.Second)
	require.NoError(t, err)
	require.True(t, claim.Acquired)
	_, err = db.Exec(
		"UPDATE provider_sessions SET refresh_lease_until = ? WHERE id = ?",
		time.Now().UTC().Add(-time.Minute),
		input.Session.ID,
	)
	require.NoError(t, err)
	_, err = repo.Resolve(context.Background(), input.LookupHash, input.Session.Binding, time.Minute)
	require.ErrorIs(t, err, auth.ErrProviderSessionUncertain)
	_, err = repo.ClaimRefresh(context.Background(), input.Session.ID, 1, "attempt-2", 5*time.Second)
	require.ErrorIs(t, err, auth.ErrProviderSessionUncertain)
}

func TestProviderSessionRepositoryLifecycleFenceRevokesExactlyAndControlsAdmission(t *testing.T) {
	repo, _ := openProviderSessionTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	first := providerSessionCreateFixture(t, now, "lifecycle-first", "lifecycle-user")
	second := providerSessionCreateFixture(t, now, "lifecycle-second", "lifecycle-user")
	other := providerSessionCreateFixture(t, now, "lifecycle-other", "other-user")
	require.NoError(t, createProviderSession(t, repo, first))
	require.NoError(t, createProviderSession(t, repo, second))
	require.NoError(t, createProviderSession(t, repo, other))

	fence, revoked, err := repo.AdvanceProviderSessionLifecycle(context.Background(), auth.ProviderSessionLifecycleTransition{
		ApplicationSubject: "lifecycle-user",
		BlockedState:       auth.ProviderSessionLifecycleSuspended,
		EventObservedAt:    now,
		Reason:             "account suspended",
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderSessionLifecycleSuspended, fence.BlockedState)
	require.EqualValues(t, 1, fence.Generation)
	require.Len(t, revoked, 2)
	require.ElementsMatch(t, []string{first.Session.ID, second.Session.ID}, []string{revoked[0].ID, revoked[1].ID})

	blocked := providerSessionCreateFixture(t, now.Add(time.Minute), "lifecycle-blocked", "lifecycle-user")
	_, err = repo.Create(context.Background(), blocked)
	require.ErrorIs(t, err, auth.ErrProviderSessionConflict)

	staleFence, staleRevoked, err := repo.AdvanceProviderSessionLifecycle(context.Background(), auth.ProviderSessionLifecycleTransition{
		ApplicationSubject: "lifecycle-user",
		BlockedState:       auth.ProviderSessionLifecycleActive,
		EventObservedAt:    now.Add(-time.Minute),
		Reason:             "stale activation",
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderSessionLifecycleSuspended, staleFence.BlockedState)
	require.Empty(t, staleRevoked)

	activeFence, _, err := repo.AdvanceProviderSessionLifecycle(context.Background(), auth.ProviderSessionLifecycleTransition{
		ApplicationSubject: "lifecycle-user",
		BlockedState:       auth.ProviderSessionLifecycleActive,
		EventObservedAt:    now.Add(time.Minute),
		Reason:             "authoritative activation",
	})
	require.NoError(t, err)
	require.Equal(t, auth.ProviderSessionLifecycleActive, activeFence.BlockedState)
	require.EqualValues(t, 2, activeFence.Generation)

	admitted := providerSessionCreateFixture(t, now.Add(2*time.Minute), "lifecycle-admitted", "lifecycle-user")
	_, err = repo.Create(context.Background(), admitted)
	require.NoError(t, err)
}

func TestProviderSessionRepositoryCredentialFenceRejectsStaleAuthentication(t *testing.T) {
	repo, _ := openProviderSessionTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	current := providerSessionCreateFixture(t, now, "credential-current", "credential-user")
	require.NoError(t, createProviderSession(t, repo, current))

	fenceAt := now.Add(time.Minute)
	fence, revoked, err := repo.AdvanceProviderSessionLifecycle(context.Background(), auth.ProviderSessionLifecycleTransition{
		ApplicationSubject:   "credential-user",
		TenantID:             "tenant-1",
		CredentialsNotBefore: fenceAt,
		EventObservedAt:      fenceAt,
		Reason:               "verified factor removed",
	})
	require.NoError(t, err)
	require.Equal(t, fenceAt, fence.CredentialsNotBefore)
	require.Len(t, revoked, 1)

	stale := providerSessionCreateFixture(t, now.Add(2*time.Minute), "credential-stale", "credential-user")
	stale.Session.Principal.AuthenticationAt = fenceAt
	stale.Session.Principal.IssuedAt = fenceAt
	_, err = repo.Create(context.Background(), stale)
	require.ErrorIs(t, err, auth.ErrProviderSessionConflict)

	fresh := providerSessionCreateFixture(t, now.Add(3*time.Minute), "credential-fresh", "credential-user")
	fresh.Session.Principal.AuthenticationAt = fenceAt.Add(time.Second)
	fresh.Session.Principal.IssuedAt = fenceAt.Add(time.Second)
	_, err = repo.Create(context.Background(), fresh)
	require.NoError(t, err)
}

func TestProviderSessionRepositoryCleanupHonorsRetentionAndRetryableRemoteWork(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	input := providerSessionCreateFixture(t, now, "cleanup", "user-cleanup")
	require.NoError(t, createProviderSession(t, repo, input))
	_, _, err := repo.Revoke(context.Background(), input.Session.ID, "logout")
	require.NoError(t, err)
	_, err = db.Exec("UPDATE provider_sessions SET updated_at = ? WHERE id = ?", now.Add(-2*time.Hour), input.Session.ID)
	require.NoError(t, err)

	result, err := repo.Cleanup(context.Background(), auth.ProviderSessionCleanupPolicy{
		Now: now, TokenRetention: time.Hour, SessionRetention: 24 * time.Hour, BatchSize: 10,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, result.TokenRecords)
	require.Zero(t, result.SessionRecords)
	requireTableCount(t, db, "provider_sessions", 1)
	requireTableCount(t, db, "provider_session_tokens", 0)

	_, err = db.Exec("UPDATE provider_sessions SET updated_at = ? WHERE id = ?", now.Add(-25*time.Hour), input.Session.ID)
	require.NoError(t, err)
	result, err = repo.Cleanup(context.Background(), auth.ProviderSessionCleanupPolicy{
		Now: now, TokenRetention: time.Hour, SessionRetention: 24 * time.Hour, BatchSize: 10,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, result.SessionRecords)
	requireTableCount(t, db, "provider_sessions", 0)

	pending := providerSessionCreateFixture(t, now, "pending-cleanup", "user-pending")
	require.NoError(t, createProviderSession(t, repo, pending))
	_, _, err = repo.Revoke(context.Background(), pending.Session.ID, "logout")
	require.NoError(t, err)
	require.NoError(t, repo.UpdateRemoteRevocation(context.Background(), pending.Session.ID, auth.ProviderRemoteRevocationOutcome{
		Status: auth.ProviderRemoteRevocationPending, Retryable: true,
	}))
	_, err = db.Exec("UPDATE provider_sessions SET updated_at = ? WHERE id = ?", now.Add(-48*time.Hour), pending.Session.ID)
	require.NoError(t, err)
	result, err = repo.Cleanup(context.Background(), auth.ProviderSessionCleanupPolicy{
		Now: now, TokenRetention: time.Hour, SessionRetention: 24 * time.Hour, BatchSize: 10,
	})
	require.NoError(t, err)
	require.Zero(t, result.TokenRecords)
	require.Zero(t, result.SessionRecords)
	requireTableCount(t, db, "provider_sessions", 1)
	requireTableCount(t, db, "provider_session_tokens", 1)
}

func TestProviderSessionRepositoryCleanupSkipsRefreshingSession(t *testing.T) {
	repo, db := openProviderSessionTestRepository(t)
	now := time.Now().UTC().Truncate(time.Second)
	input := providerSessionCreateFixture(t, now, "refresh-cleanup", "user-refresh-cleanup")
	require.NoError(t, createProviderSession(t, repo, input))
	_, err := repo.ClaimRefresh(context.Background(), input.Session.ID, 1, "attempt-cleanup", 2*time.Minute)
	require.NoError(t, err)
	_, err = db.Exec("UPDATE provider_sessions SET updated_at = ? WHERE id = ?", now.Add(-48*time.Hour), input.Session.ID)
	require.NoError(t, err)
	result, err := repo.Cleanup(context.Background(), auth.ProviderSessionCleanupPolicy{
		Now: now, TokenRetention: time.Hour, SessionRetention: 24 * time.Hour, BatchSize: 1,
	})
	require.NoError(t, err)
	require.Zero(t, result.TokenRecords)
	require.Zero(t, result.SessionRecords)
	requireTableCount(t, db, "provider_sessions", 1)
	requireTableCount(t, db, "provider_session_tokens", 1)
}

func openProviderSessionTestRepository(t *testing.T) (*ProviderSessionRepository, *bun.DB) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", "file:"+t.TempDir()+"/provider-sessions.db?_busy_timeout=5000&_journal_mode=WAL&_fk=1")
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	db := bun.NewDB(sqlDB, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close() })

	for _, name := range []string{
		"20260726100000_provider_sessions.up.sql",
		"20260726110000_freshness_invalidation_indexes.up.sql",
		"20260726120000_provider_session_authorization_fences.up.sql",
		"20260727130000_provider_session_lifecycle_fences.up.sql",
		"20260727140000_lifecycle_operation_ledger.up.sql",
		"20260727150000_provider_remote_revocation_queue.up.sql",
		"20260727160000_provider_session_reason_fingerprints.up.sql",
		"20260727170000_lifecycle_phase_leases.up.sql",
	} {
		raw, readErr := fs.ReadFile(auth.GetAuthExtrasMigrationsFS(), "data/sql/migrations/sqlite/"+name)
		require.NoError(t, readErr)
		_, execErr := db.Exec(string(raw))
		require.NoError(t, execErr)
	}
	repo, err := NewProviderSessionRepository(db)
	require.NoError(t, err)
	return repo, db
}

func providerSessionCreateFixture(t *testing.T, now time.Time, handle, subject string) auth.ProviderSessionCreate {
	t.Helper()
	principal, err := auth.NewAuthenticatedPrincipal(auth.AuthenticatedPrincipalInput{
		ApplicationSubject: subject,
		Provider:           "oidc",
		ProviderSubject:    "provider-" + subject,
		ProviderSessionID:  "provider-sid-" + subject,
		ClientID:           "client-1",
		TenantID:           "tenant-1",
		PermissionVersion:  "v1",
		IssuedAt:           now.Add(-10 * time.Minute),
	})
	require.NoError(t, err)
	localSessionID := uuid.NewString()
	principal, err = principal.BindLocalSessionID(localSessionID)
	require.NoError(t, err)
	lookup := sha256.Sum256([]byte(handle))
	return auth.ProviderSessionCreate{
		Session: auth.ProviderSession{
			ID:             uuid.NewString(),
			LocalSessionID: localSessionID,
			Principal:      auth.NewPrincipalSnapshot(principal),
			Binding: auth.ProviderSessionBinding{
				Host: "app.example.com", ApplicationID: "app", Environment: "test",
				TenantID: "tenant-1", Provider: "oidc", Issuer: "https://issuer.example.com", ClientID: "client-1",
			},
			Status:        auth.ProviderSessionAvailable,
			TokenRevision: 1,
			CreatedAt:     now.Add(-10 * time.Minute),
			LastSeenAt:    now.Add(-10 * time.Minute),
			IdleExpiresAt: now.Add(10 * time.Minute),
			MaxExpiresAt:  now.Add(time.Hour),
		},
		LookupHash: lookup[:],
		Tokens: auth.TokenEnvelope{
			Version: 1, Algorithm: "AES-256-GCM", KeyID: "key-1",
			Nonce: []byte("012345678901"), Ciphertext: []byte("sealed-provider-tokens"),
		},
	}
}

func createProviderSession(t *testing.T, repo *ProviderSessionRepository, input auth.ProviderSessionCreate) error {
	t.Helper()
	_, err := repo.Create(context.Background(), input)
	return err
}

func requireTableCount(t *testing.T, db *bun.DB, table string, expected int) {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&count))
	require.Equal(t, expected, count)
}
