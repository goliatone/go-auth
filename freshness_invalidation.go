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

type PermissionScopeInvalidator interface {
	InvalidateScope(context.Context, PermissionInvalidationScope, int) (deleted int, more bool, err error)
}

type FreshnessInvalidationResult struct {
	OperationID         string
	PermissionEntries   int
	AccountStateEntries int
	ProviderSessions    int
	More                bool
	Partial             bool
	Retryable           bool
}

type FreshnessInvalidationCoordinatorConfig struct {
	Permissions   PermissionScopeInvalidator
	AccountStates AccountStateScopeInvalidator
	Sessions      ProviderSessionScopeInvalidator
	BatchLimit    int
	ResultTTL     time.Duration
	MaxResults    int
	ActivitySink  ActivitySink
	Now           func() time.Time
}

type freshnessInvalidationCacheEntry struct {
	fingerprint string
	result      FreshnessInvalidationResult
	err         error
	expiresAt   time.Time
}

// FreshnessInvalidationCoordinator consumes normalized results only. It never
// calls a remote provider, and lifecycle consumption never repeats the
// coordinator's local-first session revocation.
type FreshnessInvalidationCoordinator struct {
	permissions   PermissionScopeInvalidator
	accountStates AccountStateScopeInvalidator
	sessions      ProviderSessionScopeInvalidator
	batchLimit    int
	resultTTL     time.Duration
	maxResults    int
	activitySink  ActivitySink
	now           func() time.Time

	group singleflight.Group
	mu    sync.Mutex
	cache map[string]freshnessInvalidationCacheEntry
}

func NewFreshnessInvalidationCoordinator(
	cfg FreshnessInvalidationCoordinatorConfig,
) (*FreshnessInvalidationCoordinator, error) {
	if cfg.Permissions == nil || cfg.AccountStates == nil {
		return nil, fmt.Errorf("%w: permission and account-state invalidators are required", ErrFreshnessPolicyInvalid)
	}
	if cfg.BatchLimit == 0 {
		cfg.BatchLimit = 100
	}
	if cfg.ResultTTL == 0 {
		cfg.ResultTTL = 24 * time.Hour
	}
	if cfg.MaxResults == 0 {
		cfg.MaxResults = 10_000
	}
	if cfg.BatchLimit <= 0 || cfg.BatchLimit > 10_000 ||
		cfg.ResultTTL <= 0 || cfg.ResultTTL > 7*24*time.Hour ||
		cfg.MaxResults <= 0 || cfg.MaxResults > 100_000 {
		return nil, ErrFreshnessPolicyInvalid
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &FreshnessInvalidationCoordinator{
		permissions: cfg.Permissions, accountStates: cfg.AccountStates,
		sessions: cfg.Sessions, batchLimit: cfg.BatchLimit,
		resultTTL: cfg.ResultTTL, maxResults: cfg.MaxResults,
		activitySink: cfg.ActivitySink, now: cfg.Now,
		cache: map[string]freshnessInvalidationCacheEntry{},
	}, nil
}

func (c *FreshnessInvalidationCoordinator) InvalidateLifecycleFreshness(
	ctx context.Context,
	request LifecycleFreshnessRequest,
) error {
	_, err := c.ConsumeLifecycleResult(ctx, request)
	return err
}

func (c *FreshnessInvalidationCoordinator) ConsumeLifecycleResult(
	ctx context.Context,
	request LifecycleFreshnessRequest,
) (FreshnessInvalidationResult, error) {
	operation := request.Operation
	if !lifecycleActionChangesFreshness(operation.Action) {
		return FreshnessInvalidationResult{OperationID: operation.OperationID}, nil
	}
	scope := PermissionInvalidationScope{
		ApplicationSubject: strings.TrimSpace(operation.Target.ApplicationSubject),
		SessionID:          strings.TrimSpace(operation.ProviderSessionID),
	}
	if scope.ApplicationSubject == "" {
		return FreshnessInvalidationResult{}, ErrFreshnessPolicyInvalid
	}
	fingerprint := strings.Join([]string{
		"lifecycle", string(operation.Action), scope.ApplicationSubject,
		scope.SessionID, string(request.Remote.Status),
	}, "\x00")
	return c.consume(
		ctx,
		"lifecycle:"+operation.OperationID,
		operation.OperationID,
		fingerprint,
		scope,
		"",
		time.Time{},
		false,
	)
}

func (c *FreshnessInvalidationCoordinator) ConsumeAuthorizationVersion(
	ctx context.Context,
	event AuthorizationVersionEvent,
	revokeSessions bool,
) (FreshnessInvalidationResult, error) {
	scope := PermissionInvalidationScope{
		ApplicationSubject: strings.TrimSpace(event.ApplicationSubject),
		TenantID:           strings.TrimSpace(event.TenantID),
	}
	if strings.TrimSpace(event.OperationID) == "" || scope.ApplicationSubject == "" ||
		strings.TrimSpace(event.Version) == "" ||
		(revokeSessions && event.CommittedAt.IsZero()) {
		return FreshnessInvalidationResult{}, ErrFreshnessPolicyInvalid
	}
	if revokeSessions && c.sessions == nil {
		return FreshnessInvalidationResult{}, ErrFreshnessInvalidationFailed
	}
	fingerprint := strings.Join([]string{
		"authorization", scope.ApplicationSubject, scope.TenantID,
		strings.TrimSpace(event.Version), event.CommittedAt.UTC().Format(time.RFC3339Nano),
		fmt.Sprint(revokeSessions),
	}, "\x00")
	return c.consume(
		ctx,
		"authorization:"+event.OperationID,
		event.OperationID,
		fingerprint,
		scope,
		strings.TrimSpace(event.Version),
		event.CommittedAt.UTC(),
		revokeSessions,
	)
}

//nolint:gocyclo // Idempotency, replay conflicts, and partial retries are kept explicit in the coordinator.
func (c *FreshnessInvalidationCoordinator) consume(
	ctx context.Context,
	cacheKey, operationID, fingerprint string,
	scope PermissionInvalidationScope,
	permissionVersion string,
	permissionVersionObservedAt time.Time,
	revokeSessions bool,
) (FreshnessInvalidationResult, error) {
	if c == nil || strings.TrimSpace(operationID) == "" {
		return FreshnessInvalidationResult{}, ErrFreshnessPolicyInvalid
	}
	if cached, ok, err := c.load(cacheKey, fingerprint); ok || err != nil {
		if err != nil {
			return FreshnessInvalidationResult{}, err
		}
		if !cached.Partial && !cached.More {
			return cached, nil
		}
	}
	_, err, _ := c.group.Do(cacheKey, func() (any, error) {
		if cached, ok, loadErr := c.load(cacheKey, fingerprint); ok || loadErr != nil {
			if loadErr != nil {
				return nil, loadErr
			}
			if !cached.Partial && !cached.More {
				return cached, nil
			}
		}
		result, runErr := c.run(
			ctx,
			operationID,
			scope,
			permissionVersion,
			permissionVersionObservedAt,
			revokeSessions,
		)
		c.store(cacheKey, fingerprint, result, runErr)
		return result, nil
	})
	if err != nil {
		return FreshnessInvalidationResult{}, err
	}
	entry, ok, loadErr := c.loadEntry(cacheKey, fingerprint)
	if loadErr != nil {
		return FreshnessInvalidationResult{}, loadErr
	}
	if !ok {
		return FreshnessInvalidationResult{}, ErrFreshnessInvalidationFailed
	}
	return entry.result, entry.err
}

func (c *FreshnessInvalidationCoordinator) run(
	ctx context.Context,
	operationID string,
	scope PermissionInvalidationScope,
	permissionVersion string,
	permissionVersionObservedAt time.Time,
	revokeSessions bool,
) (FreshnessInvalidationResult, error) {
	result := FreshnessInvalidationResult{OperationID: operationID}
	var failures []error
	deleted, more, err := c.permissions.InvalidateScope(ctx, scope, c.batchLimit)
	result.PermissionEntries = deleted
	result.More = result.More || more
	if err != nil {
		failures = append(failures, err)
	}
	deleted, more, err = c.accountStates.InvalidateAccountStates(ctx, scope, c.batchLimit)
	result.AccountStateEntries = deleted
	result.More = result.More || more
	if err != nil {
		failures = append(failures, err)
	}
	if revokeSessions {
		sessionScope := ProviderSessionInvalidationScope{
			ApplicationSubject:          scope.ApplicationSubject,
			TenantID:                    scope.TenantID,
			SessionID:                   scope.SessionID,
			PermissionVersion:           strings.TrimSpace(permissionVersion),
			PermissionVersionObservedAt: permissionVersionObservedAt.UTC(),
		}
		invalidated, sessionMore, sessionErr := c.sessions.InvalidateProviderSessions(
			ctx, sessionScope, c.batchLimit, "authorization state changed",
		)
		result.ProviderSessions = invalidated
		result.More = result.More || sessionMore
		if sessionErr != nil {
			failures = append(failures, sessionErr)
		}
	}
	result.Partial = len(failures) > 0
	result.Retryable = result.Partial || result.More
	var runErr error
	if len(failures) > 0 {
		runErr = errors.Join(append([]error{ErrFreshnessInvalidationFailed}, failures...)...)
	}
	c.emit(ctx, result, runErr)
	return result, runErr
}

func (c *FreshnessInvalidationCoordinator) load(
	cacheKey, fingerprint string,
) (FreshnessInvalidationResult, bool, error) {
	entry, ok, err := c.loadEntry(cacheKey, fingerprint)
	return entry.result, ok, err
}

func (c *FreshnessInvalidationCoordinator) loadEntry(
	cacheKey, fingerprint string,
) (freshnessInvalidationCacheEntry, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[cacheKey]
	if !ok {
		return freshnessInvalidationCacheEntry{}, false, nil
	}
	if !c.now().Before(entry.expiresAt) {
		delete(c.cache, cacheKey)
		return freshnessInvalidationCacheEntry{}, false, nil
	}
	if entry.fingerprint != fingerprint {
		return freshnessInvalidationCacheEntry{}, false, ErrProviderOperationConflict
	}
	return entry, true, nil
}

func (c *FreshnessInvalidationCoordinator) store(
	cacheKey, fingerprint string,
	result FreshnessInvalidationResult,
	err error,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for key, entry := range c.cache {
		if !now.Before(entry.expiresAt) {
			delete(c.cache, key)
		}
	}
	if len(c.cache) >= c.maxResults {
		var oldestKey string
		var oldest time.Time
		for key, entry := range c.cache {
			if oldestKey == "" || entry.expiresAt.Before(oldest) {
				oldestKey, oldest = key, entry.expiresAt
			}
		}
		delete(c.cache, oldestKey)
	}
	c.cache[cacheKey] = freshnessInvalidationCacheEntry{
		fingerprint: fingerprint, result: result, err: err,
		expiresAt: now.Add(c.resultTTL),
	}
}

func (c *FreshnessInvalidationCoordinator) emit(
	ctx context.Context,
	result FreshnessInvalidationResult,
	err error,
) {
	if c.activitySink == nil {
		return
	}
	metadata := map[string]any{
		"operation_id":          result.OperationID,
		"permission_entries":    result.PermissionEntries,
		"account_state_entries": result.AccountStateEntries,
		"provider_sessions":     result.ProviderSessions,
		"partial":               result.Partial,
		"more":                  result.More,
		"retryable":             result.Retryable,
	}
	if err != nil {
		metadata["error"] = "freshness invalidation failed"
	}
	_ = c.activitySink.Record(ctx, ActivityEvent{
		EventType: ActivityEventFreshnessInvalidation,
		Metadata:  metadata,
	})
}

func lifecycleActionChangesFreshness(action ProviderOperationAction) bool {
	switch action {
	case ProviderActionSuspend, ProviderActionActivate, ProviderActionRemoveFactor:
		return true
	default:
		return false
	}
}

var _ LifecycleFreshnessInvalidator = (*FreshnessInvalidationCoordinator)(nil)
