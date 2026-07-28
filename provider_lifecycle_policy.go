package auth

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

type LifecycleActionPolicy struct {
	Action                  ProviderOperationAction
	MutatesProvider         bool
	SecurityRestricting     bool
	LocalSessionEffect      ProviderSessionEffect
	LifecycleState          ProviderSessionLifecycleState
	CredentialsInvalidating bool
	FreshnessRequired       bool
	QueueSessionRevocation  bool
}

var lifecycleActionPolicies = map[ProviderOperationAction]LifecycleActionPolicy{
	ProviderActionInvite: {
		Action: ProviderActionInvite, MutatesProvider: true,
	},
	ProviderActionStartRecovery: {
		Action: ProviderActionStartRecovery, MutatesProvider: true,
	},
	ProviderActionSuspend: {
		Action: ProviderActionSuspend, MutatesProvider: true,
		SecurityRestricting: true, LocalSessionEffect: ProviderSessionEffectAllForUser,
		LifecycleState: ProviderSessionLifecycleSuspended, FreshnessRequired: true,
		QueueSessionRevocation: true,
	},
	ProviderActionActivate: {
		Action: ProviderActionActivate, MutatesProvider: true,
		LifecycleState: ProviderSessionLifecycleActive, FreshnessRequired: true,
	},
	ProviderActionGetAccountState: {
		Action: ProviderActionGetAccountState,
	},
	ProviderActionListFactors: {
		Action: ProviderActionListFactors,
	},
	ProviderActionRemoveFactor: {
		Action: ProviderActionRemoveFactor, MutatesProvider: true,
		SecurityRestricting: true, LocalSessionEffect: ProviderSessionEffectAllForUser,
		CredentialsInvalidating: true, FreshnessRequired: true,
		QueueSessionRevocation: true,
	},
	ProviderActionAuthorizationDetails: {
		Action: ProviderActionAuthorizationDetails,
	},
	ProviderActionAuthorizationApprove: {
		Action: ProviderActionAuthorizationApprove, MutatesProvider: true,
	},
	ProviderActionAuthorizationDeny: {
		Action: ProviderActionAuthorizationDeny, MutatesProvider: true,
	},
}

func LifecyclePolicyForAction(action ProviderOperationAction) (LifecycleActionPolicy, error) {
	policy, ok := lifecycleActionPolicies[action]
	if !ok || !action.valid() {
		return LifecycleActionPolicy{}, ErrProviderOperationInvalid
	}
	return policy, nil
}

const (
	lifecyclePermitActive uint32 = iota + 1
	lifecyclePermitConsumed
	lifecyclePermitInvalid
)

type lifecycleExecutionPermitState struct {
	store                       LifecycleOperationStore
	now                         func() time.Time
	operationID                 string
	fingerprint                 string
	operationBindingFingerprint string
	action                      ProviderOperationAction
	claimRevision               int64
	dispatchRevision            atomic.Int64
	remoteAttempt               int
	leaseOwner                  string
	leaseUntil                  time.Time
	nonce                       string
	status                      atomic.Uint32
}

// LifecycleExecutionPermit is an opaque, single-use capability minted only
// after an operation store claims one exact remote attempt. Copies share the
// same consumption state.
type LifecycleExecutionPermit struct {
	state *lifecycleExecutionPermitState
}

func (p LifecycleExecutionPermit) Validate(operation AuthorizedOperationContext) error {
	state := p.state
	if state == nil || state.status.Load() != lifecyclePermitActive ||
		strings.TrimSpace(state.nonce) == "" || state.claimRevision <= 0 || state.remoteAttempt <= 0 ||
		state.action != operation.Action ||
		state.operationID != strings.TrimSpace(operation.OperationID) {
		return fmt.Errorf("%w: invalid lifecycle execution permit", ErrProviderOperationUnauthorized)
	}
	policy, err := LifecyclePolicyForAction(operation.Action)
	if err != nil {
		return err
	}
	expected := lifecycleOperationBindingFingerprint(LifecycleCoordinationRequest{
		Operation:           operation,
		SecurityRestricting: policy.SecurityRestricting,
		LocalSessionEffect:  policy.LocalSessionEffect,
	})
	if state.operationBindingFingerprint != expected {
		return fmt.Errorf("%w: lifecycle execution permit binding mismatch", ErrProviderOperationUnauthorized)
	}
	return nil
}

// Consume validates this permit against the live operation claim and consumes
// it before provider transport. It permits an explicitly selected in-memory
// store for development and compatibility use.
func (p LifecycleExecutionPermit) Consume(
	ctx context.Context,
	operation AuthorizedOperationContext,
) error {
	return p.consume(ctx, operation, false)
}

// ConsumeForHardenedMutation additionally requires durable operation
// authority. Hardened provider adapters must use this method.
func (p LifecycleExecutionPermit) ConsumeForHardenedMutation(
	ctx context.Context,
	operation AuthorizedOperationContext,
) error {
	return p.consume(ctx, operation, true)
}

//nolint:gocyclo // Permit consumption validates every live durable-claim binding explicitly.
func (p LifecycleExecutionPermit) consume(
	ctx context.Context,
	operation AuthorizedOperationContext,
	requireDurable bool,
) error {
	if err := p.Validate(operation); err != nil {
		return err
	}
	state := p.state
	if state.store == nil || (requireDurable && !state.store.Durable()) {
		return fmt.Errorf("%w: durable lifecycle operation authority is required", ErrProviderOperationUnauthorized)
	}
	current, err := state.store.Load(ctx, state.operationID)
	if err != nil {
		return errorsJoinUnauthorized(err)
	}
	now := state.now().UTC()
	if current.Fingerprint != state.fingerprint ||
		current.Action != state.action ||
		current.Revision != state.claimRevision ||
		current.RemoteAttempt != state.remoteAttempt ||
		current.RemotePhase != LifecyclePhaseInFlight ||
		current.RemoteLeaseOwner != state.leaseOwner ||
		current.RemoteLeaseUntil.IsZero() ||
		!current.RemoteLeaseUntil.Equal(state.leaseUntil) ||
		!now.Before(current.RemoteLeaseUntil) {
		return fmt.Errorf("%w: stale lifecycle execution permit", ErrProviderOperationUnauthorized)
	}
	if !state.status.CompareAndSwap(lifecyclePermitActive, lifecyclePermitConsumed) {
		return fmt.Errorf("%w: lifecycle execution permit already used", ErrProviderOperationUnauthorized)
	}
	claimed, err := state.store.Advance(ctx, current.Revision, current)
	if err != nil {
		return errorsJoinUnauthorized(err)
	}
	state.dispatchRevision.Store(claimed.Revision)
	return nil
}

func errorsJoinUnauthorized(err error) error {
	return fmt.Errorf("%w: lifecycle operation authority unavailable: %v", ErrProviderOperationUnauthorized, err)
}

func newLifecycleExecutionPermit(
	store LifecycleOperationStore,
	now func() time.Time,
	operation AuthorizedOperationContext,
	request LifecycleCoordinationRequest,
	record LifecycleOperationRecord,
	nonce string,
) LifecycleExecutionPermit {
	state := &lifecycleExecutionPermitState{
		store:                       store,
		now:                         now,
		operationID:                 operation.OperationID,
		fingerprint:                 record.Fingerprint,
		operationBindingFingerprint: lifecycleOperationBindingFingerprint(request),
		action:                      operation.Action,
		claimRevision:               record.Revision,
		remoteAttempt:               record.RemoteAttempt,
		leaseOwner:                  record.RemoteLeaseOwner,
		leaseUntil:                  record.RemoteLeaseUntil,
		nonce:                       nonce,
	}
	state.dispatchRevision.Store(record.Revision)
	state.status.Store(lifecyclePermitActive)
	return LifecycleExecutionPermit{state: state}
}

func (p LifecycleExecutionPermit) invalidate() {
	if p.state != nil {
		p.state.status.CompareAndSwap(lifecyclePermitActive, lifecyclePermitInvalid)
	}
}

func (p LifecycleExecutionPermit) consumed() bool {
	return p.state != nil && p.state.status.Load() == lifecyclePermitConsumed
}

func (p LifecycleExecutionPermit) currentClaim(
	ctx context.Context,
) (LifecycleOperationRecord, error) {
	if !p.consumed() || p.state.store == nil {
		return LifecycleOperationRecord{}, fmt.Errorf(
			"%w: lifecycle execution permit was not consumed",
			ErrProviderOperationUnauthorized,
		)
	}
	state := p.state
	current, err := state.store.Load(ctx, state.operationID)
	if err != nil {
		return LifecycleOperationRecord{}, errorsJoinUnauthorized(err)
	}
	if current.Fingerprint != state.fingerprint ||
		current.Action != state.action ||
		current.Revision != state.dispatchRevision.Load() ||
		current.RemoteAttempt != state.remoteAttempt ||
		current.RemotePhase != LifecyclePhaseInFlight ||
		current.RemoteLeaseOwner != state.leaseOwner ||
		!current.RemoteLeaseUntil.Equal(state.leaseUntil) {
		return current, fmt.Errorf(
			"%w: lifecycle execution claim changed during provider dispatch",
			ErrProviderOperationUnauthorized,
		)
	}
	return current, nil
}

func (p LifecycleExecutionPermit) IdempotencyKey() string {
	if p.state == nil || strings.TrimSpace(p.state.nonce) == "" {
		return ""
	}
	return p.state.fingerprint
}

type CoordinatedProviderOperationExecutor interface {
	ExecuteCoordinatedProviderOperation(
		context.Context,
		AuthorizedOperationContext,
		LifecycleExecutionPermit,
	) (ProviderOperationOutcome, error)
}

type CoordinatedProviderOperationExecutorFunc func(
	context.Context,
	AuthorizedOperationContext,
	LifecycleExecutionPermit,
) (ProviderOperationOutcome, error)

func (f CoordinatedProviderOperationExecutorFunc) ExecuteCoordinatedProviderOperation(
	ctx context.Context,
	operation AuthorizedOperationContext,
	permit LifecycleExecutionPermit,
) (ProviderOperationOutcome, error) {
	if f == nil {
		return ProviderOperationOutcome{}, ErrProviderOperationUnsupported
	}
	return f(ctx, operation, permit)
}
