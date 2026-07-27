package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	Operation           AuthorizedOperationContext
	SecurityRestricting bool
	LocalSessionEffect  ProviderSessionEffect
	Remote              ProviderOperationExecutor
}

type LifecycleCoordinationResult struct {
	OperationID string
	Local       ProviderOperationOutcome
	Remote      ProviderOperationOutcome
	Freshness   ProviderOperationOutcome
}

type LifecycleCoordinatorConfig struct {
	LocalInvalidator ProviderSessionLocalInvalidator
	Freshness        LifecycleFreshnessInvalidator
	ResultTTL        time.Duration
	MaxResults       int
	Clock            func() time.Time
}

type LifecycleCoordinator struct {
	localInvalidator ProviderSessionLocalInvalidator
	freshness        LifecycleFreshnessInvalidator
	resultTTL        time.Duration
	maxResults       int
	clock            func() time.Time

	group singleflight.Group
	mu    sync.Mutex
	cache map[string]lifecycleCachedResult
}

type lifecycleCachedResult struct {
	fingerprint  string
	result       LifecycleCoordinationResult
	localErr     error
	remoteErr    error
	freshnessErr error
	expiresAt    time.Time
}

func NewLifecycleCoordinator(config LifecycleCoordinatorConfig) (*LifecycleCoordinator, error) {
	if config.Freshness == nil {
		return nil, ErrProviderOperationInvalid
	}
	if config.ResultTTL == 0 {
		config.ResultTTL = 24 * time.Hour
	}
	if config.MaxResults == 0 {
		config.MaxResults = 10_000
	}
	if config.ResultTTL <= 0 || config.ResultTTL > 7*24*time.Hour ||
		config.MaxResults <= 0 || config.MaxResults > 100_000 {
		return nil, ErrProviderOperationInvalid
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &LifecycleCoordinator{
		localInvalidator: config.LocalInvalidator,
		freshness:        config.Freshness,
		resultTTL:        config.ResultTTL,
		maxResults:       config.MaxResults,
		clock:            config.Clock,
		cache:            make(map[string]lifecycleCachedResult),
	}, nil
}

//nolint:gocyclo // Idempotency, local-first revocation, and partial provider outcomes remain explicit.
func (c *LifecycleCoordinator) Coordinate(
	ctx context.Context,
	request LifecycleCoordinationRequest,
) (LifecycleCoordinationResult, error) {
	if c == nil || request.Remote == nil {
		return LifecycleCoordinationResult{}, ErrProviderOperationInvalid
	}
	operation := request.Operation
	if err := operation.Validate(operation.Action, operation.Environment, operation.Target.Provider); err != nil {
		return LifecycleCoordinationResult{}, err
	}
	if request.SecurityRestricting {
		switch request.LocalSessionEffect {
		case ProviderSessionEffectCurrent, ProviderSessionEffectNamed:
			if strings.TrimSpace(operation.ProviderSessionID) == "" {
				return LifecycleCoordinationResult{}, fmt.Errorf("%w: provider session ID is required", ErrProviderOperationInvalid)
			}
		case ProviderSessionEffectAllForUser:
			if strings.TrimSpace(operation.Target.ApplicationSubject) == "" {
				return LifecycleCoordinationResult{}, fmt.Errorf("%w: application subject is required", ErrProviderOperationInvalid)
			}
		default:
			return LifecycleCoordinationResult{}, fmt.Errorf("%w: local session effect is required", ErrProviderOperationInvalid)
		}
		if c.localInvalidator == nil {
			return LifecycleCoordinationResult{}, fmt.Errorf("%w: local invalidator is required", ErrProviderOperationInvalid)
		}
	}
	fingerprint := lifecycleFingerprint(request)
	if cached, ok, err := c.load(operation.OperationID, fingerprint); ok || err != nil {
		if err != nil {
			return LifecycleCoordinationResult{}, err
		}
		if cached.result.Local.Status != ProviderOperationFailed &&
			cached.result.Freshness.Status != ProviderOperationFailed {
			return cached.result, cached.err()
		}
	}

	_, groupErr, _ := c.group.Do(operation.OperationID, func() (any, error) {
		if cached, ok, err := c.load(operation.OperationID, fingerprint); ok || err != nil {
			if err != nil {
				return nil, err
			}
			switch {
			case cached.result.Local.Status == ProviderOperationFailed:
				attempt := c.execute(ctx, request)
				c.store(operation.OperationID, fingerprint, attempt)
			case cached.result.Freshness.Status == ProviderOperationFailed:
				freshnessErr := c.freshness.InvalidateLifecycleFreshness(ctx, LifecycleFreshnessRequest{
					Operation: request.Operation,
					Remote:    cached.result.Remote,
				})
				cached.freshnessErr = freshnessErr
				if freshnessErr == nil {
					cached.result.Freshness.Status = ProviderOperationSucceeded
				}
				c.store(operation.OperationID, fingerprint, lifecycleAttempt{
					result: cached.result, localErr: cached.localErr,
					remoteErr: cached.remoteErr, freshnessErr: cached.freshnessErr,
				})
			}
			return nil, nil
		}
		attempt := c.execute(ctx, request)
		c.store(operation.OperationID, fingerprint, attempt)
		return nil, nil
	})
	if groupErr != nil {
		return LifecycleCoordinationResult{}, groupErr
	}
	cached, ok, err := c.load(operation.OperationID, fingerprint)
	if err != nil {
		return LifecycleCoordinationResult{}, err
	}
	if !ok {
		return LifecycleCoordinationResult{}, ErrProviderOperationInvalid
	}
	return cached.result, cached.err()
}

func (c *LifecycleCoordinator) execute(
	ctx context.Context,
	request LifecycleCoordinationRequest,
) lifecycleAttempt {
	result := LifecycleCoordinationResult{OperationID: request.Operation.OperationID}
	if request.SecurityRestricting {
		var err error
		switch request.LocalSessionEffect {
		case ProviderSessionEffectCurrent, ProviderSessionEffectNamed:
			err = c.localInvalidator.InvalidateProviderSession(
				ctx, request.Operation.ProviderSessionID, request.Operation.Reason,
			)
		case ProviderSessionEffectAllForUser:
			err = c.localInvalidator.InvalidateUserProviderSessions(
				ctx, request.Operation.Target.ApplicationSubject, request.Operation.Reason,
			)
		}
		if err != nil {
			result.Local = ProviderOperationOutcome{
				Status: ProviderOperationFailed, ProviderSessionEffect: request.LocalSessionEffect,
			}
			return lifecycleAttempt{result: result, localErr: err}
		}
		result.Local = ProviderOperationOutcome{
			Status: ProviderOperationSucceeded, ProviderSessionEffect: request.LocalSessionEffect,
		}
	} else {
		result.Local = ProviderOperationOutcome{
			Status: ProviderOperationAlreadyComplete, ProviderSessionEffect: ProviderSessionEffectNone,
		}
	}

	remote, remoteErr := request.Remote.ExecuteProviderOperation(ctx, request.Operation)
	if outcomeErr := remote.Validate(); outcomeErr != nil {
		remoteErr = errors.Join(remoteErr, outcomeErr)
		remote.Status = ProviderOperationFailed
		remote.Retryable = false
	}
	result.Remote = remote

	freshnessErr := c.freshness.InvalidateLifecycleFreshness(ctx, LifecycleFreshnessRequest{
		Operation: request.Operation,
		Remote:    remote,
	})
	if freshnessErr != nil {
		result.Freshness = ProviderOperationOutcome{Status: ProviderOperationFailed}
	} else {
		result.Freshness = ProviderOperationOutcome{Status: ProviderOperationSucceeded}
	}
	return lifecycleAttempt{result: result, remoteErr: remoteErr, freshnessErr: freshnessErr}
}

type lifecycleAttempt struct {
	result       LifecycleCoordinationResult
	localErr     error
	remoteErr    error
	freshnessErr error
}

func (c *LifecycleCoordinator) load(
	operationID, fingerprint string,
) (lifecycleCachedResult, bool, error) {
	now := c.clock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	cached, ok := c.cache[operationID]
	if !ok {
		return lifecycleCachedResult{}, false, nil
	}
	if cached.fingerprint != fingerprint {
		return lifecycleCachedResult{}, false, fmt.Errorf("%w: operation ID reuse mismatch", ErrProviderOperationConflict)
	}
	return cached, true, nil
}

func (c *LifecycleCoordinator) store(
	operationID, fingerprint string,
	attempt lifecycleAttempt,
) {
	now := c.clock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if len(c.cache) >= c.maxResults {
		var oldestID string
		var oldest time.Time
		for id, value := range c.cache {
			if oldestID == "" || value.expiresAt.Before(oldest) {
				oldestID, oldest = id, value.expiresAt
			}
		}
		delete(c.cache, oldestID)
	}
	c.cache[operationID] = lifecycleCachedResult{
		fingerprint: fingerprint, result: attempt.result,
		localErr: attempt.localErr, remoteErr: attempt.remoteErr,
		freshnessErr: attempt.freshnessErr, expiresAt: now.Add(c.resultTTL),
	}
}

func (r lifecycleCachedResult) err() error {
	return errors.Join(r.localErr, r.remoteErr, r.freshnessErr)
}

func (c *LifecycleCoordinator) pruneLocked(now time.Time) {
	for operationID, result := range c.cache {
		if !now.Before(result.expiresAt) {
			delete(c.cache, operationID)
		}
	}
}

func lifecycleFingerprint(request LifecycleCoordinationRequest) string {
	operation := request.Operation
	return strings.Join([]string{
		string(operation.Action),
		strings.TrimSpace(operation.Target.Provider),
		strings.TrimSpace(operation.Target.ApplicationSubject),
		strings.TrimSpace(operation.Target.Subject),
		strings.TrimSpace(operation.Target.ObjectID),
		strings.TrimSpace(operation.ProviderSessionID),
		strings.TrimSpace(operation.Permission),
		strings.TrimSpace(operation.Actor.ID),
		strings.TrimSpace(operation.Actor.Type),
		strings.TrimSpace(operation.Reason),
		strings.TrimSpace(operation.Environment),
		operation.AuthorizedAt.UTC().Format(time.RFC3339Nano),
		string(request.LocalSessionEffect),
		fmt.Sprintf("%t", request.SecurityRestricting),
	}, "\x00")
}
