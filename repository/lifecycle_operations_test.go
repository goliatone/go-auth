package repository

import (
	"context"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/stretchr/testify/require"
)

func TestLifecycleOperationRepositoryClaimsAndAdvancesWithRevisionFence(t *testing.T) {
	_, db := openProviderSessionTestRepository(t)
	store, err := NewLifecycleOperationRepository(db)
	require.NoError(t, err)
	claim := auth.LifecycleOperationClaim{
		OperationID: "operation-1",
		Fingerprint: "sha256:fingerprint-1",
		Action:      auth.ProviderActionSuspend,
	}
	first, disposition, err := store.Claim(context.Background(), claim)
	require.NoError(t, err)
	require.Equal(t, auth.LifecycleOperationClaimed, disposition)
	require.EqualValues(t, 1, first.Revision)

	replayed, disposition, err := store.Claim(context.Background(), claim)
	require.NoError(t, err)
	require.Equal(t, auth.LifecycleOperationExisting, disposition)
	require.Equal(t, first, replayed)

	_, _, err = store.Claim(context.Background(), auth.LifecycleOperationClaim{
		OperationID: claim.OperationID,
		Fingerprint: "sha256:different",
		Action:      claim.Action,
	})
	require.ErrorIs(t, err, auth.ErrProviderOperationConflict)

	first.LocalPhase = auth.LifecyclePhaseSucceeded
	first.Local = auth.ProviderOperationOutcome{
		Status:                auth.ProviderOperationSucceeded,
		ProviderSessionEffect: auth.ProviderSessionEffectAllForUser,
	}
	first.LocalLeaseOwner = "local-worker"
	first.LocalLeaseUntil = time.Now().UTC().Add(time.Minute)
	first.FreshnessLeaseOwner = "freshness-worker"
	first.FreshnessLeaseUntil = time.Now().UTC().Add(2 * time.Minute)
	advanced, err := store.Advance(context.Background(), first.Revision, first)
	require.NoError(t, err)
	require.EqualValues(t, 2, advanced.Revision)
	loaded, err := store.Load(context.Background(), claim.OperationID)
	require.NoError(t, err)
	require.Equal(t, first.LocalLeaseOwner, loaded.LocalLeaseOwner)
	require.WithinDuration(t, first.LocalLeaseUntil, loaded.LocalLeaseUntil, time.Millisecond)
	require.Equal(t, first.FreshnessLeaseOwner, loaded.FreshnessLeaseOwner)
	require.WithinDuration(t, first.FreshnessLeaseUntil, loaded.FreshnessLeaseUntil, time.Millisecond)

	_, err = store.Advance(context.Background(), first.Revision, first)
	require.ErrorIs(t, err, auth.ErrLifecycleOperationConflict)
}

func TestLifecycleOperationRepositoryClaimsExpiredRemoteWork(t *testing.T) {
	_, db := openProviderSessionTestRepository(t)
	store, err := NewLifecycleOperationRepository(db)
	require.NoError(t, err)
	record, _, err := store.Claim(context.Background(), auth.LifecycleOperationClaim{
		OperationID: "operation-pending",
		Fingerprint: "sha256:pending",
		Action:      auth.ProviderActionSuspend,
	})
	require.NoError(t, err)
	record.RemotePhase = auth.LifecyclePhaseInFlight
	record.RemoteLeaseOwner = "dead-worker"
	record.RemoteLeaseUntil = time.Now().UTC().Add(-time.Minute)
	record, err = store.Advance(context.Background(), record.Revision, record)
	require.NoError(t, err)

	claimed, err := store.ClaimPending(context.Background(), auth.LifecycleOperationPendingPolicy{
		Now:        time.Now().UTC(),
		LeaseOwner: "reconciler-1",
		Lease:      30 * time.Second,
		Limit:      10,
	})
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, auth.LifecyclePhasePendingReconcile, claimed[0].RemotePhase)
	require.Equal(t, "reconciler-1", claimed[0].RemoteLeaseOwner)
	competing, err := store.ClaimPending(context.Background(), auth.LifecycleOperationPendingPolicy{
		Now:        time.Now().UTC(),
		LeaseOwner: "reconciler-2",
		Lease:      30 * time.Second,
		Limit:      10,
	})
	require.NoError(t, err)
	require.Empty(t, competing)
}
