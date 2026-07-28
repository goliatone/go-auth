package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type revokerStub struct {
	order   *[]string
	current atomic.Int32
	all     atomic.Int32
	err     error
}

func (r *revokerStub) InvalidateProviderSession(context.Context, string, string) error {
	r.current.Add(1)
	if r.order != nil {
		*r.order = append(*r.order, "local")
	}
	return r.err
}
func (r *revokerStub) InvalidateUserProviderSessions(context.Context, string, string) error {
	r.all.Add(1)
	if r.order != nil {
		*r.order = append(*r.order, "local")
	}
	return r.err
}

func coordinatorOperation() AuthorizedOperationContext {
	operation := validAuthorizedOperation(ProviderActionSuspend)
	operation.Target.ApplicationSubject = "app-user-1"
	operation.Target.Subject = "provider-user-1"
	operation.ProviderSessionID = "provider-session-1"
	return operation
}

func newTestLifecycleCoordinator(
	config LifecycleCoordinatorConfig,
) (*LifecycleCoordinator, error) {
	if config.OperationStore == nil {
		config.OperationStore = NewInMemoryLifecycleOperationStore(config.Clock)
	}
	return NewLifecycleCoordinator(config)
}

func TestLifecycleCoordinatorOrdersLocalRemoteFreshnessAndReplaysOnce(t *testing.T) {
	var order []string
	revoker := &revokerStub{order: &order}
	var remoteCalls, freshnessCalls atomic.Int32
	coordinator, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: revoker,
		Freshness: LifecycleFreshnessInvalidatorFunc(func(context.Context, LifecycleFreshnessRequest) error {
			freshnessCalls.Add(1)
			order = append(order, "freshness")
			return nil
		}),
	})
	require.NoError(t, err)
	request := LifecycleCoordinationRequest{
		Operation:           coordinatorOperation(),
		SecurityRestricting: true,
		LocalSessionEffect:  ProviderSessionEffectAllForUser,
		Remote: ProviderOperationExecutorFunc(func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
			remoteCalls.Add(1)
			order = append(order, "remote")
			return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
		}),
	}
	first, err := coordinator.Coordinate(context.Background(), request)
	require.NoError(t, err)
	second, err := coordinator.Coordinate(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, []string{"local", "remote", "freshness"}, order)
	require.Equal(t, int32(1), revoker.all.Load())
	require.Equal(t, int32(1), remoteCalls.Load())
	require.Equal(t, int32(1), freshnessCalls.Load())
}

func TestLifecycleCoordinatorNeverCallsRemoteWhenLocalRevocationFails(t *testing.T) {
	localErr := errors.New("local store unavailable")
	revoker := &revokerStub{err: localErr}
	var remoteCalls atomic.Int32
	coordinator, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: revoker,
		Freshness: LifecycleFreshnessInvalidatorFunc(func(context.Context, LifecycleFreshnessRequest) error {
			return nil
		}),
	})
	require.NoError(t, err)
	result, err := coordinator.Coordinate(context.Background(), LifecycleCoordinationRequest{
		Operation: coordinatorOperation(), SecurityRestricting: true,
		LocalSessionEffect: ProviderSessionEffectCurrent,
		Remote: ProviderOperationExecutorFunc(func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
			remoteCalls.Add(1)
			return ProviderOperationOutcome{}, nil
		}),
	})
	require.ErrorIs(t, err, localErr)
	require.Equal(t, ProviderOperationFailed, result.Local.Status)
	require.Zero(t, remoteCalls.Load())
}

func TestLifecycleCoordinatorReturnsRemoteAndFreshnessPartialOutcomes(t *testing.T) {
	remoteErr := errors.New("provider unavailable")
	freshnessErr := errors.New("cache unavailable")
	coordinator, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: &revokerStub{},
		Freshness: LifecycleFreshnessInvalidatorFunc(func(context.Context, LifecycleFreshnessRequest) error {
			return freshnessErr
		}),
	})
	require.NoError(t, err)
	result, err := coordinator.Coordinate(context.Background(), LifecycleCoordinationRequest{
		Operation: coordinatorOperation(), SecurityRestricting: true,
		LocalSessionEffect: ProviderSessionEffectAllForUser,
		Remote: ProviderOperationExecutorFunc(func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
			return ProviderOperationOutcome{Status: ProviderOperationPending}, remoteErr
		}),
	})
	require.ErrorIs(t, err, remoteErr)
	require.ErrorIs(t, err, freshnessErr)
	require.Equal(t, ProviderOperationSucceeded, result.Local.Status)
	require.Equal(t, ProviderOperationPending, result.Remote.Status)
	require.Equal(t, ProviderOperationFailed, result.Freshness.Status)
}

func TestLifecycleCoordinatorRejectsInvalidRemoteOutcomes(t *testing.T) {
	t.Parallel()

	for name, status := range map[string]ProviderOperationStatus{
		"missing": "",
		"unknown": "invented",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var observed ProviderOperationOutcome
			coordinator, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
				LocalInvalidator: &revokerStub{},
				Freshness: LifecycleFreshnessInvalidatorFunc(func(_ context.Context, request LifecycleFreshnessRequest) error {
					observed = request.Remote
					return nil
				}),
			})
			require.NoError(t, err)
			result, err := coordinator.Coordinate(context.Background(), LifecycleCoordinationRequest{
				Operation: coordinatorOperation(),
				Remote: ProviderOperationExecutorFunc(func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
					return ProviderOperationOutcome{
						Status: status, Retryable: true, ProviderRequestID: "provider-request",
					}, nil
				}),
			})

			require.ErrorIs(t, err, ErrProviderOperationInvalid)
			require.Equal(t, ProviderOperationFailed, result.Remote.Status)
			require.False(t, result.Remote.Retryable)
			require.Equal(t, "provider-request", result.Remote.ProviderRequestID)
			require.Equal(t, result.Remote, observed)
		})
	}
}

func TestLifecycleCoordinatorRetriesOnlyFailedFreshnessOnReplay(t *testing.T) {
	var remoteCalls, freshnessCalls atomic.Int32
	coordinator, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: &revokerStub{},
		Freshness: LifecycleFreshnessInvalidatorFunc(func(context.Context, LifecycleFreshnessRequest) error {
			if freshnessCalls.Add(1) == 1 {
				return errors.New("temporary cache outage")
			}
			return nil
		}),
	})
	require.NoError(t, err)
	request := LifecycleCoordinationRequest{
		Operation: coordinatorOperation(),
		Remote: ProviderOperationExecutorFunc(func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
			remoteCalls.Add(1)
			return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
		}),
	}
	first, err := coordinator.Coordinate(context.Background(), request)
	require.Error(t, err)
	require.Equal(t, ProviderOperationFailed, first.Freshness.Status)
	second, err := coordinator.Coordinate(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, ProviderOperationSucceeded, second.Freshness.Status)
	require.Equal(t, int32(1), remoteCalls.Load())
	require.Equal(t, int32(2), freshnessCalls.Load())
}

func TestLifecycleCoordinatorRejectsOperationIDReuseWithDifferentTarget(t *testing.T) {
	coordinator, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: &revokerStub{},
		Freshness: LifecycleFreshnessInvalidatorFunc(func(context.Context, LifecycleFreshnessRequest) error {
			return nil
		}),
	})
	require.NoError(t, err)
	request := LifecycleCoordinationRequest{
		Operation: coordinatorOperation(),
		Remote: ProviderOperationExecutorFunc(func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
			return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
		}),
	}
	_, err = coordinator.Coordinate(context.Background(), request)
	require.NoError(t, err)
	request.Operation.Target.Subject = "different-provider-user"
	_, err = coordinator.Coordinate(context.Background(), request)
	require.ErrorIs(t, err, ErrProviderOperationConflict)

	request.Operation.Target.Subject = coordinatorOperation().Target.Subject
	request.Operation.Actor.ID = "different-actor"
	_, err = coordinator.Coordinate(context.Background(), request)
	require.ErrorIs(t, err, ErrProviderOperationConflict)
}

func TestLifecycleCoordinatorCoalescesConcurrentReplay(t *testing.T) {
	var remoteCalls atomic.Int32
	coordinator, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: &revokerStub{},
		Freshness: LifecycleFreshnessInvalidatorFunc(func(context.Context, LifecycleFreshnessRequest) error {
			return nil
		}),
	})
	require.NoError(t, err)
	request := LifecycleCoordinationRequest{
		Operation: coordinatorOperation(),
		Remote: ProviderOperationExecutorFunc(func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
			remoteCalls.Add(1)
			time.Sleep(5 * time.Millisecond)
			return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
		}),
	}
	var wait sync.WaitGroup
	for range 8 {
		wait.Go(func() {
			_, callErr := coordinator.Coordinate(context.Background(), request)
			require.NoError(t, callErr)
		})
	}
	wait.Wait()
	require.Equal(t, int32(1), remoteCalls.Load())
}

func TestLifecycleCoordinatorResumesCompletedOperationAcrossInstances(t *testing.T) {
	store := NewInMemoryLifecycleOperationStore(nil)
	var localCalls, remoteCalls, freshnessCalls atomic.Int32
	revoker := &revokerStub{}
	freshness := LifecycleFreshnessInvalidatorFunc(func(context.Context, LifecycleFreshnessRequest) error {
		freshnessCalls.Add(1)
		return nil
	})
	first, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: revoker,
		Freshness:        freshness,
		OperationStore:   store,
	})
	require.NoError(t, err)
	revoker.order = nil
	request := LifecycleCoordinationRequest{
		Operation:           coordinatorOperation(),
		SecurityRestricting: true,
		LocalSessionEffect:  ProviderSessionEffectAllForUser,
		Remote: ProviderOperationExecutorFunc(func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
			remoteCalls.Add(1)
			return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
		}),
	}
	_, err = first.Coordinate(context.Background(), request)
	require.NoError(t, err)
	localCalls.Store(revoker.all.Load())

	restarted, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: revoker,
		Freshness:        freshness,
		OperationStore:   store,
	})
	require.NoError(t, err)
	_, err = restarted.Coordinate(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, int32(1), localCalls.Load())
	require.Equal(t, int32(1), revoker.all.Load())
	require.Equal(t, int32(1), remoteCalls.Load())
	require.Equal(t, int32(1), freshnessCalls.Load())
}

func TestLifecycleCoordinatorRecoversExpiredLocalPhaseAfterRestart(t *testing.T) {
	now := time.Date(2026, 7, 27, 18, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := NewInMemoryLifecycleOperationStore(clock)
	request := LifecycleCoordinationRequest{
		Operation:           coordinatorOperation(),
		SecurityRestricting: true,
		LocalSessionEffect:  ProviderSessionEffectAllForUser,
		Remote: ProviderOperationExecutorFunc(
			func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
				return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
			},
		),
	}
	fingerprint, err := lifecycleFingerprint(request)
	require.NoError(t, err)
	record, _, err := store.Claim(context.Background(), LifecycleOperationClaim{
		OperationID: request.Operation.OperationID,
		Fingerprint: fingerprint,
		Action:      request.Operation.Action,
	})
	require.NoError(t, err)
	record.LocalPhase = LifecyclePhaseInFlight
	record.LocalLeaseOwner = "crashed-worker"
	record.LocalLeaseUntil = now.Add(-time.Second)
	_, err = store.Advance(context.Background(), record.Revision, record)
	require.NoError(t, err)

	revoker := &revokerStub{}
	var freshnessCalls atomic.Int32
	restarted, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: revoker,
		Freshness: LifecycleFreshnessInvalidatorFunc(
			func(context.Context, LifecycleFreshnessRequest) error {
				freshnessCalls.Add(1)
				return nil
			},
		),
		OperationStore: store,
		PhaseLease:     30 * time.Second,
		Clock:          clock,
	})
	require.NoError(t, err)

	result, err := restarted.Coordinate(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, ProviderOperationSucceeded, result.Local.Status)
	require.EqualValues(t, 1, revoker.all.Load())
	require.EqualValues(t, 1, freshnessCalls.Load())
	stored, err := store.Load(context.Background(), request.Operation.OperationID)
	require.NoError(t, err)
	require.True(t, stored.Completed)
	require.Empty(t, stored.LocalLeaseOwner)
	require.True(t, stored.LocalLeaseUntil.IsZero())
}

func TestLifecycleCoordinatorDoesNotStealLiveLocalPhaseLease(t *testing.T) {
	now := time.Date(2026, 7, 27, 18, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := NewInMemoryLifecycleOperationStore(clock)
	request := LifecycleCoordinationRequest{
		Operation:           coordinatorOperation(),
		SecurityRestricting: true,
		LocalSessionEffect:  ProviderSessionEffectAllForUser,
		Remote: ProviderOperationExecutorFunc(
			func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
				return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
			},
		),
	}
	fingerprint, err := lifecycleFingerprint(request)
	require.NoError(t, err)
	record, _, err := store.Claim(context.Background(), LifecycleOperationClaim{
		OperationID: request.Operation.OperationID,
		Fingerprint: fingerprint,
		Action:      request.Operation.Action,
	})
	require.NoError(t, err)
	record.LocalPhase = LifecyclePhaseInFlight
	record.LocalLeaseOwner = "live-worker"
	record.LocalLeaseUntil = now.Add(time.Minute)
	_, err = store.Advance(context.Background(), record.Revision, record)
	require.NoError(t, err)

	revoker := &revokerStub{}
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: revoker,
		Freshness: LifecycleFreshnessInvalidatorFunc(
			func(context.Context, LifecycleFreshnessRequest) error { return nil },
		),
		OperationStore: store,
		PhaseLease:     30 * time.Second,
		Clock:          clock,
	})
	require.NoError(t, err)

	_, err = coordinator.Coordinate(context.Background(), request)
	require.ErrorIs(t, err, ErrProviderOperationPending)
	require.Zero(t, revoker.all.Load())
}

func TestLifecycleCoordinatorRecoversExpiredFreshnessPhaseAfterRestart(t *testing.T) {
	now := time.Date(2026, 7, 27, 18, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := NewInMemoryLifecycleOperationStore(clock)
	request := LifecycleCoordinationRequest{
		Operation:           coordinatorOperation(),
		SecurityRestricting: true,
		LocalSessionEffect:  ProviderSessionEffectAllForUser,
		Remote: ProviderOperationExecutorFunc(
			func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
				return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
			},
		),
	}
	fingerprint, err := lifecycleFingerprint(request)
	require.NoError(t, err)
	record, _, err := store.Claim(context.Background(), LifecycleOperationClaim{
		OperationID: request.Operation.OperationID,
		Fingerprint: fingerprint,
		Action:      request.Operation.Action,
	})
	require.NoError(t, err)
	record.LocalPhase = LifecyclePhaseSucceeded
	record.Local = ProviderOperationOutcome{
		Status:                ProviderOperationSucceeded,
		ProviderSessionEffect: ProviderSessionEffectAllForUser,
	}
	record.RemotePhase = LifecyclePhaseSucceeded
	record.Remote = ProviderOperationOutcome{Status: ProviderOperationSucceeded}
	record.FreshnessPhase = LifecyclePhaseInFlight
	record.FreshnessLeaseOwner = "crashed-worker"
	record.FreshnessLeaseUntil = now.Add(-time.Second)
	_, err = store.Advance(context.Background(), record.Revision, record)
	require.NoError(t, err)

	var remoteCalls, freshnessCalls atomic.Int32
	request.Remote = ProviderOperationExecutorFunc(
		func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
			remoteCalls.Add(1)
			return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
		},
	)
	restarted, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: &revokerStub{},
		Freshness: LifecycleFreshnessInvalidatorFunc(
			func(context.Context, LifecycleFreshnessRequest) error {
				freshnessCalls.Add(1)
				return nil
			},
		),
		OperationStore: store,
		PhaseLease:     30 * time.Second,
		Clock:          clock,
	})
	require.NoError(t, err)

	result, err := restarted.Coordinate(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, ProviderOperationSucceeded, result.Freshness.Status)
	require.Zero(t, remoteCalls.Load())
	require.EqualValues(t, 1, freshnessCalls.Load())
	stored, err := store.Load(context.Background(), request.Operation.OperationID)
	require.NoError(t, err)
	require.Empty(t, stored.FreshnessLeaseOwner)
	require.True(t, stored.FreshnessLeaseUntil.IsZero())
}

func TestLifecycleCoordinatorRejectsInMemoryStoreWhenDurabilityRequired(t *testing.T) {
	_, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
		Freshness:      LifecycleFreshnessInvalidatorFunc(func(context.Context, LifecycleFreshnessRequest) error { return nil }),
		OperationStore: NewInMemoryLifecycleOperationStore(nil),
		RequireDurable: true,
	})
	require.ErrorIs(t, err, ErrProviderOperationInvalid)
}

func TestLifecycleCoordinatorRequiresExplicitOperationStore(t *testing.T) {
	_, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
		Freshness: LifecycleFreshnessInvalidatorFunc(
			func(context.Context, LifecycleFreshnessRequest) error { return nil },
		),
	})
	require.ErrorIs(t, err, ErrProviderOperationInvalid)
}

func TestLifecycleCoordinatorDerivesSecurityEffectAndRequiresCoordinatedExecutor(t *testing.T) {
	revoker := &revokerStub{}
	coordinator, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: revoker,
		Freshness: LifecycleFreshnessInvalidatorFunc(func(context.Context, LifecycleFreshnessRequest) error {
			return nil
		}),
		RequirePermits: true,
	})
	require.NoError(t, err)
	request := LifecycleCoordinationRequest{
		Operation:           coordinatorOperation(),
		SecurityRestricting: false,
		LocalSessionEffect:  ProviderSessionEffectNone,
		Remote: ProviderOperationExecutorFunc(func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
			return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
		}),
	}
	result, err := coordinator.Coordinate(context.Background(), request)
	require.ErrorIs(t, err, ErrProviderOperationUnauthorized)
	require.Equal(t, int32(1), revoker.all.Load())
	require.Equal(t, ProviderSessionEffectAllForUser, result.Local.ProviderSessionEffect)

	operation := coordinatorOperation()
	operation.OperationID = "permit-operation"
	var permitObserved bool
	result, err = coordinator.Coordinate(context.Background(), LifecycleCoordinationRequest{
		Operation: operation,
		Remote: coordinatedExecutorStub{
			coordinated: func(ctx context.Context, operation AuthorizedOperationContext, permit LifecycleExecutionPermit) (ProviderOperationOutcome, error) {
				permitObserved = permit.Consume(ctx, operation) == nil
				return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
			},
		},
	})
	require.NoError(t, err)
	require.True(t, permitObserved)
	require.Equal(t, ProviderOperationSucceeded, result.Remote.Status)
}

func TestLifecycleExecutionPermitIsSingleUseAndInvalidAfterDispatch(t *testing.T) {
	store := NewInMemoryLifecycleOperationStore(nil)
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: &revokerStub{},
		Freshness: LifecycleFreshnessInvalidatorFunc(
			func(context.Context, LifecycleFreshnessRequest) error { return nil },
		),
		OperationStore: store,
		RequirePermits: true,
	})
	require.NoError(t, err)
	operation := coordinatorOperation()
	operation.OperationID = "single-use-permit"
	var captured LifecycleExecutionPermit
	var replayErr error
	_, err = coordinator.Coordinate(context.Background(), LifecycleCoordinationRequest{
		Operation: operation,
		Remote: coordinatedExecutorStub{
			coordinated: func(
				ctx context.Context,
				operation AuthorizedOperationContext,
				permit LifecycleExecutionPermit,
			) (ProviderOperationOutcome, error) {
				captured = permit
				require.NoError(t, permit.Consume(ctx, operation))
				replayErr = permit.Consume(ctx, operation)
				return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
			},
		},
	})
	require.NoError(t, err)
	require.ErrorIs(t, replayErr, ErrProviderOperationUnauthorized)
	require.ErrorIs(t, captured.Validate(operation), ErrProviderOperationUnauthorized)
	require.ErrorIs(
		t,
		captured.Consume(context.Background(), operation),
		ErrProviderOperationUnauthorized,
	)

	operation.OperationID = "unconsumed-permit"
	result, err := coordinator.Coordinate(context.Background(), LifecycleCoordinationRequest{
		Operation: operation,
		Remote: coordinatedExecutorStub{
			coordinated: func(
				context.Context,
				AuthorizedOperationContext,
				LifecycleExecutionPermit,
			) (ProviderOperationOutcome, error) {
				return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
			},
		},
	})
	require.ErrorIs(t, err, ErrProviderOperationUnauthorized)
	require.Equal(t, ProviderOperationFailed, result.Remote.Status)
}

func TestLifecycleExecutionPermitRejectsStaleLedgerRevisionAndAttempt(t *testing.T) {
	store := NewInMemoryLifecycleOperationStore(nil)
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: &revokerStub{},
		Freshness: LifecycleFreshnessInvalidatorFunc(
			func(context.Context, LifecycleFreshnessRequest) error { return nil },
		),
		OperationStore: store,
		RequirePermits: true,
	})
	require.NoError(t, err)
	operation := coordinatorOperation()
	operation.OperationID = "stale-permit-revision"
	var consumeErr error
	result, err := coordinator.Coordinate(context.Background(), LifecycleCoordinationRequest{
		Operation: operation,
		Remote: coordinatedExecutorStub{
			coordinated: func(
				ctx context.Context,
				operation AuthorizedOperationContext,
				permit LifecycleExecutionPermit,
			) (ProviderOperationOutcome, error) {
				current, loadErr := store.Load(ctx, operation.OperationID)
				require.NoError(t, loadErr)
				current.RemoteAttempt++
				_, advanceErr := store.Advance(ctx, current.Revision, current)
				require.NoError(t, advanceErr)
				consumeErr = permit.Consume(ctx, operation)
				return ProviderOperationOutcome{Status: ProviderOperationFailed}, consumeErr
			},
		},
	})
	require.ErrorIs(t, err, ErrProviderOperationUnauthorized)
	require.ErrorIs(t, err, ErrProviderOperationPending)
	require.ErrorIs(t, consumeErr, ErrProviderOperationUnauthorized)
	require.Equal(t, operation.OperationID, result.OperationID)
	require.Equal(t, ProviderOperationSucceeded, result.Local.Status)
}

func TestLifecycleCoordinatorReconcilesClaimedPendingOperation(t *testing.T) {
	store := NewInMemoryLifecycleOperationStore(nil)
	var remoteCalls atomic.Int32
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: &revokerStub{},
		Freshness: LifecycleFreshnessInvalidatorFunc(
			func(context.Context, LifecycleFreshnessRequest) error { return nil },
		),
		OperationStore: store,
	})
	require.NoError(t, err)
	request := LifecycleCoordinationRequest{
		Operation: coordinatorOperation(),
		Remote: ProviderOperationExecutorFunc(
			func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error) {
				remoteCalls.Add(1)
				return ProviderOperationOutcome{
					Status: ProviderOperationPending, Retryable: true,
				}, ErrProviderOperationPending
			},
		),
	}
	first, err := coordinator.Coordinate(context.Background(), request)
	require.ErrorIs(t, err, ErrProviderOperationPending)
	require.Equal(t, ProviderOperationPending, first.Remote.Status)

	now := time.Now().UTC()
	claims, err := store.ClaimPending(context.Background(), LifecycleOperationPendingPolicy{
		Now: now, LeaseOwner: "reconciler-1", Lease: 30 * time.Second, Limit: 1,
	})
	require.NoError(t, err)
	require.Len(t, claims, 1)
	competing, err := store.ClaimPending(context.Background(), LifecycleOperationPendingPolicy{
		Now: now, LeaseOwner: "reconciler-2", Lease: 30 * time.Second, Limit: 1,
	})
	require.NoError(t, err)
	require.Empty(t, competing)
	reconciled, err := coordinator.ReconcileLifecycleOperation(
		context.Background(),
		LifecycleOperationReconciliation{
			Request: request,
			Claim:   claims[0],
			Remote:  ProviderOperationOutcome{Status: ProviderOperationSucceeded},
		},
	)
	require.NoError(t, err)
	require.Equal(t, ProviderOperationSucceeded, reconciled.Remote.Status)

	replayed, err := coordinator.Coordinate(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, reconciled, replayed)
	require.EqualValues(t, 1, remoteCalls.Load())

	_, err = coordinator.ReconcileLifecycleOperation(
		context.Background(),
		LifecycleOperationReconciliation{
			Request: request,
			Claim:   claims[0],
			Remote:  ProviderOperationOutcome{Status: ProviderOperationSucceeded},
		},
	)
	require.ErrorIs(t, err, ErrLifecycleOperationConflict)
}

func TestLifecycleFingerprintIncludesActionSpecificExecutorFields(t *testing.T) {
	coordinator, err := newTestLifecycleCoordinator(LifecycleCoordinatorConfig{
		LocalInvalidator: &revokerStub{},
		Freshness: LifecycleFreshnessInvalidatorFunc(
			func(context.Context, LifecycleFreshnessRequest) error { return nil },
		),
	})
	require.NoError(t, err)
	operation := coordinatorOperation()
	operation.OperationID = "action-specific-fingerprint"
	first := lifecycleFingerprintExecutor{value: "allow-last=false"}
	_, err = coordinator.Coordinate(context.Background(), LifecycleCoordinationRequest{
		Operation: operation,
		Remote:    first,
	})
	require.NoError(t, err)
	_, err = coordinator.Coordinate(context.Background(), LifecycleCoordinationRequest{
		Operation: operation,
		Remote:    lifecycleFingerprintExecutor{value: "allow-last=true"},
	})
	require.ErrorIs(t, err, ErrProviderOperationConflict)
}

type lifecycleFingerprintExecutor struct {
	value string
}

func (e lifecycleFingerprintExecutor) ExecuteProviderOperation(
	context.Context,
	AuthorizedOperationContext,
) (ProviderOperationOutcome, error) {
	return ProviderOperationOutcome{Status: ProviderOperationSucceeded}, nil
}

func (e lifecycleFingerprintExecutor) ProviderOperationFingerprintFields() []ProviderOperationFingerprintField {
	return []ProviderOperationFingerprintField{{Name: "action_input", Value: e.value}}
}

type coordinatedExecutorStub struct {
	coordinated func(context.Context, AuthorizedOperationContext, LifecycleExecutionPermit) (ProviderOperationOutcome, error)
}

func (s coordinatedExecutorStub) ExecuteProviderOperation(
	context.Context,
	AuthorizedOperationContext,
) (ProviderOperationOutcome, error) {
	return ProviderOperationOutcome{}, ErrProviderOperationUnauthorized
}

func (s coordinatedExecutorStub) ExecuteCoordinatedProviderOperation(
	ctx context.Context,
	operation AuthorizedOperationContext,
	permit LifecycleExecutionPermit,
) (ProviderOperationOutcome, error) {
	return s.coordinated(ctx, operation, permit)
}
