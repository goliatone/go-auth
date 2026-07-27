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

func TestLifecycleCoordinatorOrdersLocalRemoteFreshnessAndReplaysOnce(t *testing.T) {
	var order []string
	revoker := &revokerStub{order: &order}
	var remoteCalls, freshnessCalls atomic.Int32
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
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
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
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
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
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
			coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
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
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
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
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
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
	coordinator, err := NewLifecycleCoordinator(LifecycleCoordinatorConfig{
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
