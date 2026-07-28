package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

type ProviderOperationExecutor interface {
	ExecuteProviderOperation(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error)
}

type ProviderOperationExecutorFunc func(context.Context, AuthorizedOperationContext) (ProviderOperationOutcome, error)

func (f ProviderOperationExecutorFunc) ExecuteProviderOperation(
	ctx context.Context,
	operation AuthorizedOperationContext,
) (ProviderOperationOutcome, error) {
	if f == nil {
		return ProviderOperationOutcome{}, ErrProviderOperationUnsupported
	}
	return f(ctx, operation)
}

// ProviderOperationFingerprintField binds an action-specific executor input to
// the durable operation fingerprint without storing the raw input.
type ProviderOperationFingerprintField struct {
	Name  string
	Value string
}

// ProviderOperationFingerprintContributor is implemented by concrete
// executors whose request contains action inputs outside
// AuthorizedOperationContext.
type ProviderOperationFingerprintContributor interface {
	ProviderOperationFingerprintFields() []ProviderOperationFingerprintField
}

type LifecycleFreshnessRequest struct {
	Operation AuthorizedOperationContext
	Remote    ProviderOperationOutcome
}

type LifecycleFreshnessInvalidator interface {
	InvalidateLifecycleFreshness(context.Context, LifecycleFreshnessRequest) error
}

type LifecycleFreshnessInvalidatorFunc func(context.Context, LifecycleFreshnessRequest) error

func (f LifecycleFreshnessInvalidatorFunc) InvalidateLifecycleFreshness(
	ctx context.Context,
	request LifecycleFreshnessRequest,
) error {
	if f == nil {
		return ErrProviderOperationUnsupported
	}
	return f(ctx, request)
}

type LifecycleCoordinationRequest struct {
	Operation AuthorizedOperationContext
	// Deprecated: hardened coordination derives this from the action policy.
	SecurityRestricting bool
	// Deprecated: hardened coordination derives this from the action policy.
	LocalSessionEffect ProviderSessionEffect
	Remote             ProviderOperationExecutor
}

type LifecycleCoordinationResult struct {
	OperationID string
	Local       ProviderOperationOutcome
	Remote      ProviderOperationOutcome
	Freshness   ProviderOperationOutcome
}

// LifecycleOperationReconciliation completes a pending remote phase from an
// authoritative provider observation. Claim must be a live record returned by
// LifecycleOperationStore.ClaimPending.
type LifecycleOperationReconciliation struct {
	Request LifecycleCoordinationRequest
	Claim   LifecycleOperationRecord
	Remote  ProviderOperationOutcome
}

type LifecycleCoordinatorConfig struct {
	LocalInvalidator     ProviderSessionLocalInvalidator
	LifecycleInvalidator ProviderSessionLifecycleInvalidator
	Freshness            LifecycleFreshnessInvalidator
	OperationStore       LifecycleOperationStore
	RequireDurable       bool
	RequirePermits       bool
	RemoteLease          time.Duration
	// Deprecated: retained for source compatibility with the previous
	// process-local result cache. Durable stores own retention.
	ResultTTL time.Duration
	// Deprecated: retained for source compatibility.
	MaxResults int
	Clock      func() time.Time
}

type LifecycleCoordinator struct {
	localInvalidator     ProviderSessionLocalInvalidator
	lifecycleInvalidator ProviderSessionLifecycleInvalidator
	freshness            LifecycleFreshnessInvalidator
	store                LifecycleOperationStore
	requirePermits       bool
	remoteLease          time.Duration
	clock                func() time.Time
	group                singleflight.Group
}

func NewLifecycleCoordinator(config LifecycleCoordinatorConfig) (*LifecycleCoordinator, error) {
	if config.Freshness == nil {
		return nil, ErrProviderOperationInvalid
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.OperationStore == nil {
		return nil, fmt.Errorf("%w: explicit operation store is required", ErrProviderOperationInvalid)
	}
	if config.RequireDurable && !config.OperationStore.Durable() {
		return nil, fmt.Errorf("%w: durable operation store is required", ErrProviderOperationInvalid)
	}
	if config.RemoteLease == 0 {
		config.RemoteLease = 30 * time.Second
	}
	if config.RemoteLease < 5*time.Second || config.RemoteLease > 5*time.Minute {
		return nil, fmt.Errorf("%w: remote lease must be between 5 seconds and 5 minutes", ErrProviderOperationInvalid)
	}
	return &LifecycleCoordinator{
		localInvalidator:     config.LocalInvalidator,
		lifecycleInvalidator: config.LifecycleInvalidator,
		freshness:            config.Freshness,
		store:                config.OperationStore,
		requirePermits:       config.RequirePermits,
		remoteLease:          config.RemoteLease,
		clock:                config.Clock,
	}, nil
}

// Coordinate advances one durable operation state machine. Completed phases
// are loaded from the store and are never replayed.
func (c *LifecycleCoordinator) Coordinate(
	ctx context.Context,
	request LifecycleCoordinationRequest,
) (LifecycleCoordinationResult, error) {
	if c == nil || c.store == nil || request.Remote == nil {
		return LifecycleCoordinationResult{}, ErrProviderOperationInvalid
	}
	policy, err := LifecyclePolicyForAction(request.Operation.Action)
	if err != nil {
		return LifecycleCoordinationResult{}, err
	}
	request.SecurityRestricting = policy.SecurityRestricting
	request.LocalSessionEffect = policy.LocalSessionEffect
	if err := validateLifecycleCoordinationRequest(c, request); err != nil {
		return LifecycleCoordinationResult{}, err
	}
	fingerprint, err := lifecycleFingerprint(request)
	if err != nil {
		return LifecycleCoordinationResult{}, err
	}
	value, err, _ := c.group.Do(request.Operation.OperationID, func() (any, error) {
		return c.coordinateOnce(ctx, request, fingerprint)
	})
	if value == nil {
		return LifecycleCoordinationResult{}, err
	}
	result, ok := value.(LifecycleCoordinationResult)
	if !ok {
		return LifecycleCoordinationResult{}, ErrProviderOperationInvalid
	}
	return result, err
}

// ReconcileLifecycleOperation persists an authoritative outcome for one
// leased pending operation, then resumes freshness and completion. It never
// dispatches the provider mutation.
func (c *LifecycleCoordinator) ReconcileLifecycleOperation(
	ctx context.Context,
	reconciliation LifecycleOperationReconciliation,
) (LifecycleCoordinationResult, error) {
	if c == nil || c.store == nil || reconciliation.Request.Remote == nil {
		return LifecycleCoordinationResult{}, ErrProviderOperationInvalid
	}
	if err := reconciliation.Remote.Validate(); err != nil {
		return LifecycleCoordinationResult{}, err
	}
	request := reconciliation.Request
	policy, err := LifecyclePolicyForAction(request.Operation.Action)
	if err != nil {
		return LifecycleCoordinationResult{}, err
	}
	request.SecurityRestricting = policy.SecurityRestricting
	request.LocalSessionEffect = policy.LocalSessionEffect
	if err := validateLifecycleCoordinationRequest(c, request); err != nil {
		return LifecycleCoordinationResult{}, err
	}
	fingerprint, err := lifecycleFingerprint(request)
	if err != nil {
		return LifecycleCoordinationResult{}, err
	}
	value, reconcileErr, _ := c.group.Do(request.Operation.OperationID, func() (any, error) {
		record, loadErr := c.store.Load(ctx, request.Operation.OperationID)
		if loadErr != nil {
			return LifecycleCoordinationResult{}, loadErr
		}
		claim := reconciliation.Claim
		now := c.clock().UTC()
		if record.Fingerprint != fingerprint ||
			claim.OperationID != record.OperationID ||
			claim.Fingerprint != record.Fingerprint ||
			claim.Revision != record.Revision ||
			claim.RemoteAttempt != record.RemoteAttempt ||
			claim.RemoteLeaseOwner == "" ||
			claim.RemoteLeaseOwner != record.RemoteLeaseOwner ||
			claim.RemoteLeaseUntil.IsZero() ||
			!claim.RemoteLeaseUntil.Equal(record.RemoteLeaseUntil) ||
			!now.Before(record.RemoteLeaseUntil) ||
			record.RemotePhase != LifecyclePhasePendingReconcile {
			return lifecycleResultFromRecord(record), ErrLifecycleOperationConflict
		}
		record.Remote = reconciliation.Remote
		record.RemoteLeaseOwner = ""
		record.RemoteLeaseUntil = time.Time{}
		record.RemotePhase = lifecycleRemoteTerminalPhase(reconciliation.Remote)
		stored, advanceErr := c.store.Advance(ctx, record.Revision, record)
		if advanceErr != nil {
			return lifecycleResultFromRecord(record), advanceErr
		}
		record = stored
		record, freshnessErr := c.runFreshnessPhase(ctx, request, record)
		record, completionErr := c.completeOperation(ctx, record)
		return lifecycleResultFromRecord(record), errors.Join(freshnessErr, completionErr)
	})
	if value == nil {
		return LifecycleCoordinationResult{}, reconcileErr
	}
	result, ok := value.(LifecycleCoordinationResult)
	if !ok {
		return LifecycleCoordinationResult{}, ErrProviderOperationInvalid
	}
	return result, reconcileErr
}

func validateLifecycleCoordinationRequest(
	c *LifecycleCoordinator,
	request LifecycleCoordinationRequest,
) error {
	operation := request.Operation
	if err := operation.Validate(operation.Action, operation.Environment, operation.Target.Provider); err != nil {
		return err
	}
	if !request.SecurityRestricting {
		return nil
	}
	switch request.LocalSessionEffect {
	case ProviderSessionEffectCurrent, ProviderSessionEffectNamed:
		if strings.TrimSpace(operation.ProviderSessionID) == "" {
			return fmt.Errorf("%w: provider session ID is required", ErrProviderOperationInvalid)
		}
	case ProviderSessionEffectAllForUser:
		if strings.TrimSpace(operation.Target.ApplicationSubject) == "" {
			return fmt.Errorf("%w: application subject is required", ErrProviderOperationInvalid)
		}
	default:
		return fmt.Errorf("%w: local session effect is required", ErrProviderOperationInvalid)
	}
	if c.localInvalidator == nil && c.lifecycleInvalidator == nil {
		return fmt.Errorf("%w: local invalidator is required", ErrProviderOperationInvalid)
	}
	return nil
}

func (c *LifecycleCoordinator) coordinateOnce(
	ctx context.Context,
	request LifecycleCoordinationRequest,
	fingerprint string,
) (LifecycleCoordinationResult, error) {
	record, _, err := c.store.Claim(ctx, LifecycleOperationClaim{
		OperationID: request.Operation.OperationID,
		Fingerprint: fingerprint,
		Action:      request.Operation.Action,
	})
	if err != nil {
		return LifecycleCoordinationResult{}, err
	}
	if record.Completed {
		return lifecycleResultFromRecord(record), nil
	}

	record, localErr := c.runLocalPhase(ctx, request, record)
	if localErr != nil {
		return lifecycleResultFromRecord(record), localErr
	}
	record, remoteErr := c.runRemotePhase(ctx, request, record)
	record, freshnessErr := c.runFreshnessPhase(ctx, request, record)
	record, completionErr := c.completeOperation(ctx, record)
	return lifecycleResultFromRecord(record), errors.Join(remoteErr, freshnessErr, completionErr)
}

func (c *LifecycleCoordinator) runLocalPhase(
	ctx context.Context,
	request LifecycleCoordinationRequest,
	record LifecycleOperationRecord,
) (LifecycleOperationRecord, error) {
	if record.LocalPhase == LifecyclePhaseSucceeded || record.LocalPhase == LifecyclePhaseSkipped {
		return record, nil
	}
	if record.LocalPhase == LifecyclePhaseInFlight {
		return record, ErrProviderOperationPending
	}
	claimed := record
	claimed.LocalPhase = LifecyclePhaseInFlight
	next, err := c.store.Advance(ctx, record.Revision, claimed)
	if err != nil {
		return c.reloadAfterConflict(ctx, record.OperationID, err)
	}
	record = next

	if !request.SecurityRestricting {
		record.LocalPhase = LifecyclePhaseSkipped
		record.Local = ProviderOperationOutcome{
			Status:                ProviderOperationAlreadyComplete,
			ProviderSessionEffect: ProviderSessionEffectNone,
		}
		return c.store.Advance(ctx, record.Revision, record)
	}
	if c.lifecycleInvalidator != nil {
		policy, policyErr := LifecyclePolicyForAction(request.Operation.Action)
		if policyErr != nil {
			return record, policyErr
		}
		transition := ProviderSessionLifecycleTransition{
			ApplicationSubject:    request.Operation.Target.ApplicationSubject,
			TenantID:              "",
			BlockedState:          policy.LifecycleState,
			Ordering:              ProviderSessionLifecycleRepositoryOrder,
			Reason:                request.Operation.Reason,
			QueueRemoteRevocation: policy.QueueSessionRevocation,
		}
		if policy.CredentialsInvalidating {
			transition.AdvanceCredentials = true
		}
		_, _, err = c.lifecycleInvalidator.ApplyProviderSessionLifecycle(ctx, transition)
	} else {
		switch request.LocalSessionEffect {
		case ProviderSessionEffectCurrent, ProviderSessionEffectNamed:
			err = c.localInvalidator.InvalidateProviderSession(
				ctx,
				request.Operation.ProviderSessionID,
				request.Operation.Reason,
			)
		case ProviderSessionEffectAllForUser:
			err = c.localInvalidator.InvalidateUserProviderSessions(
				ctx,
				request.Operation.Target.ApplicationSubject,
				request.Operation.Reason,
			)
		}
	}
	if err != nil {
		record.LocalPhase = LifecyclePhaseFailed
		record.Local = ProviderOperationOutcome{
			Status: ProviderOperationFailed, ProviderSessionEffect: request.LocalSessionEffect,
		}
		stored, storeErr := c.store.Advance(ctx, record.Revision, record)
		return stored, errors.Join(err, storeErr)
	}
	record.LocalPhase = LifecyclePhaseSucceeded
	record.Local = ProviderOperationOutcome{
		Status: ProviderOperationSucceeded, ProviderSessionEffect: request.LocalSessionEffect,
	}
	return c.store.Advance(ctx, record.Revision, record)
}

func (c *LifecycleCoordinator) runRemotePhase(
	ctx context.Context,
	request LifecycleCoordinationRequest,
	record LifecycleOperationRecord,
) (LifecycleOperationRecord, error) {
	switch record.RemotePhase {
	case LifecyclePhaseSucceeded, LifecyclePhaseFailed, LifecyclePhaseSkipped:
		return record, nil
	case LifecyclePhaseInFlight:
		if record.RemoteLeaseUntil.IsZero() || c.clock().UTC().Before(record.RemoteLeaseUntil) {
			return record, ErrProviderOperationPending
		}
		record.RemotePhase = LifecyclePhasePendingReconcile
		next, err := c.store.Advance(ctx, record.Revision, record)
		return next, errors.Join(ErrProviderOperationPending, err)
	case LifecyclePhasePendingReconcile:
		return record, ErrProviderOperationPending
	}
	leaseOwner, err := randomProviderSessionValue(18)
	if err != nil {
		return record, err
	}
	record.RemotePhase = LifecyclePhaseInFlight
	record.RemoteAttempt++
	record.RemoteLeaseOwner = leaseOwner
	record.RemoteLeaseUntil = c.clock().UTC().Add(c.remoteLease)
	next, err := c.store.Advance(ctx, record.Revision, record)
	if err != nil {
		return c.reloadAfterConflict(ctx, record.OperationID, err)
	}
	record = next

	permitNonce, permitErr := randomProviderSessionValue(18)
	if permitErr != nil {
		return record, permitErr
	}
	permit := newLifecycleExecutionPermit(
		c.store,
		c.clock,
		request.Operation,
		request,
		record,
		permitNonce,
	)
	var outcome ProviderOperationOutcome
	var remoteErr error
	if coordinated, ok := request.Remote.(CoordinatedProviderOperationExecutor); ok {
		outcome, remoteErr = coordinated.ExecuteCoordinatedProviderOperation(ctx, request.Operation, permit)
		if c.requirePermits && !permit.consumed() {
			outcome = ProviderOperationOutcome{Status: ProviderOperationFailed}
			remoteErr = errors.Join(
				remoteErr,
				fmt.Errorf("%w: lifecycle execution permit was not consumed", ErrProviderOperationUnauthorized),
			)
		}
		if permit.consumed() {
			current, claimErr := permit.currentClaim(ctx)
			if claimErr != nil {
				latest, loadErr := c.store.Load(ctx, record.OperationID)
				return latest, errors.Join(
					remoteErr,
					ErrProviderOperationPending,
					claimErr,
					loadErr,
				)
			}
			record = current
		}
		permit.invalidate()
	} else if c.requirePermits {
		outcome = ProviderOperationOutcome{Status: ProviderOperationFailed}
		remoteErr = fmt.Errorf("%w: coordinated executor is required", ErrProviderOperationUnauthorized)
	} else {
		outcome, remoteErr = request.Remote.ExecuteProviderOperation(ctx, request.Operation)
	}
	if outcomeErr := outcome.Validate(); outcomeErr != nil {
		remoteErr = errors.Join(remoteErr, outcomeErr)
		outcome.Status = ProviderOperationFailed
		outcome.Retryable = false
	}
	record.Remote = outcome
	record.RemoteLeaseOwner = ""
	record.RemoteLeaseUntil = time.Time{}
	record.RemotePhase = lifecycleRemoteTerminalPhase(outcome)
	if remoteErr != nil && outcome.Retryable {
		record.RemotePhase = LifecyclePhasePendingReconcile
	}
	stored, storeErr := c.store.Advance(ctx, record.Revision, record)
	if storeErr != nil {
		current, conflictErr := c.reloadAfterConflict(ctx, record.OperationID, storeErr)
		return current, errors.Join(remoteErr, conflictErr)
	}
	return stored, errors.Join(remoteErr, storeErr)
}

func (c *LifecycleCoordinator) runFreshnessPhase(
	ctx context.Context,
	request LifecycleCoordinationRequest,
	record LifecycleOperationRecord,
) (LifecycleOperationRecord, error) {
	if record.FreshnessPhase == LifecyclePhaseSucceeded || record.FreshnessPhase == LifecyclePhaseSkipped {
		return record, nil
	}
	if record.FreshnessPhase == LifecyclePhaseInFlight {
		return record, ErrProviderOperationPending
	}
	record.FreshnessPhase = LifecyclePhaseInFlight
	next, err := c.store.Advance(ctx, record.Revision, record)
	if err != nil {
		return c.reloadAfterConflict(ctx, record.OperationID, err)
	}
	record = next
	policy, policyErr := LifecyclePolicyForAction(request.Operation.Action)
	if policyErr != nil {
		return record, policyErr
	}
	if policy.LifecycleState == ProviderSessionLifecycleActive &&
		(record.Remote.Status == ProviderOperationSucceeded ||
			record.Remote.Status == ProviderOperationAlreadyComplete) {
		if c.lifecycleInvalidator == nil {
			return record, fmt.Errorf("%w: lifecycle invalidator is required for activation", ErrProviderOperationInvalid)
		}
		_, _, lifecycleErr := c.lifecycleInvalidator.ApplyProviderSessionLifecycle(
			ctx,
			ProviderSessionLifecycleTransition{
				ApplicationSubject: request.Operation.Target.ApplicationSubject,
				BlockedState:       ProviderSessionLifecycleActive,
				Ordering:           ProviderSessionLifecycleRepositoryOrder,
				Reason:             request.Operation.Reason,
			},
		)
		if lifecycleErr != nil {
			record.FreshnessPhase = LifecyclePhaseFailed
			record.Freshness = ProviderOperationOutcome{Status: ProviderOperationFailed}
			stored, storeErr := c.store.Advance(ctx, record.Revision, record)
			return stored, errors.Join(lifecycleErr, storeErr)
		}
	}
	if !policy.FreshnessRequired {
		record.FreshnessPhase = LifecyclePhaseSkipped
		record.Freshness = ProviderOperationOutcome{Status: ProviderOperationAlreadyComplete}
		return c.store.Advance(ctx, record.Revision, record)
	}
	freshnessErr := c.freshness.InvalidateLifecycleFreshness(ctx, LifecycleFreshnessRequest{
		Operation: request.Operation,
		Remote:    record.Remote,
	})
	if freshnessErr != nil {
		record.FreshnessPhase = LifecyclePhaseFailed
		record.Freshness = ProviderOperationOutcome{Status: ProviderOperationFailed}
	} else {
		record.FreshnessPhase = LifecyclePhaseSucceeded
		record.Freshness = ProviderOperationOutcome{Status: ProviderOperationSucceeded}
	}
	stored, storeErr := c.store.Advance(ctx, record.Revision, record)
	return stored, errors.Join(freshnessErr, storeErr)
}

func (c *LifecycleCoordinator) completeOperation(
	ctx context.Context,
	record LifecycleOperationRecord,
) (LifecycleOperationRecord, error) {
	if record.Completed {
		return record, nil
	}
	localDone := record.LocalPhase == LifecyclePhaseSucceeded || record.LocalPhase == LifecyclePhaseSkipped
	remoteDone := record.RemotePhase == LifecyclePhaseSucceeded ||
		record.RemotePhase == LifecyclePhaseFailed ||
		record.RemotePhase == LifecyclePhaseSkipped
	freshnessDone := record.FreshnessPhase == LifecyclePhaseSucceeded ||
		record.FreshnessPhase == LifecyclePhaseSkipped
	if !localDone || !remoteDone || !freshnessDone {
		return record, nil
	}
	record.Completed = true
	return c.store.Advance(ctx, record.Revision, record)
}

func (c *LifecycleCoordinator) reloadAfterConflict(
	ctx context.Context,
	operationID string,
	err error,
) (LifecycleOperationRecord, error) {
	if !errors.Is(err, ErrLifecycleOperationConflict) {
		return LifecycleOperationRecord{}, err
	}
	current, loadErr := c.store.Load(ctx, operationID)
	return current, errors.Join(ErrProviderOperationPending, loadErr)
}

func lifecycleResultFromRecord(record LifecycleOperationRecord) LifecycleCoordinationResult {
	return LifecycleCoordinationResult{
		OperationID: record.OperationID,
		Local:       record.Local,
		Remote:      record.Remote,
		Freshness:   record.Freshness,
	}
}

func lifecycleRemoteTerminalPhase(outcome ProviderOperationOutcome) LifecycleOperationPhase {
	switch outcome.Status {
	case ProviderOperationPending:
		return LifecyclePhasePendingReconcile
	case ProviderOperationFailed, ProviderOperationConflict:
		return LifecyclePhaseFailed
	default:
		return LifecyclePhaseSucceeded
	}
}

func lifecycleOperationBindingFingerprint(request LifecycleCoordinationRequest) string {
	operation := request.Operation
	canonical := strings.Join([]string{
		"lifecycle-operation-binding-v3",
		string(operation.Action),
		strings.TrimSpace(operation.Target.Provider),
		strings.TrimSpace(operation.Target.ApplicationSubject),
		strings.TrimSpace(operation.Target.Subject),
		strings.TrimSpace(operation.Target.ObjectID),
		strings.TrimSpace(operation.ProviderSessionID),
		strings.TrimSpace(operation.Permission),
		strings.TrimSpace(operation.Actor.ID),
		strings.TrimSpace(operation.Actor.Type),
		string(FingerprintProviderAuditValue(operation.Reason)),
		strings.TrimSpace(operation.Environment),
		string(FingerprintProviderAuditValue(operation.RequestID)),
		operation.AuthorizedAt.UTC().Format(time.RFC3339Nano),
		string(request.LocalSessionEffect),
		fmt.Sprintf("%t", request.SecurityRestricting),
	}, "\x00")
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("sha256:%x", sum)
}

func lifecycleFingerprint(request LifecycleCoordinationRequest) (string, error) {
	fields := []string{
		"lifecycle-operation-v3",
		lifecycleOperationBindingFingerprint(request),
	}
	if contributor, ok := request.Remote.(ProviderOperationFingerprintContributor); ok {
		actionFields := slices.Clone(contributor.ProviderOperationFingerprintFields())
		slices.SortFunc(actionFields, func(left, right ProviderOperationFingerprintField) int {
			if byName := strings.Compare(left.Name, right.Name); byName != 0 {
				return byName
			}
			return strings.Compare(left.Value, right.Value)
		})
		seen := make(map[string]struct{}, len(actionFields))
		for _, field := range actionFields {
			name := strings.TrimSpace(field.Name)
			if !validLifecycleFingerprintFieldName(name) || len(field.Value) > 4096 {
				return "", fmt.Errorf("%w: invalid action fingerprint field", ErrProviderOperationInvalid)
			}
			if _, duplicate := seen[name]; duplicate {
				return "", fmt.Errorf("%w: duplicate action fingerprint field", ErrProviderOperationInvalid)
			}
			seen[name] = struct{}{}
			fields = append(fields, name, string(FingerprintProviderAuditValue(field.Value)))
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x00")))
	return fmt.Sprintf("sha256:%x", sum), nil
}

func validLifecycleFingerprintFieldName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') &&
			char != '_' && char != '-' && char != '.' {
			return false
		}
	}
	return true
}
