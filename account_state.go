package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// AccountState is the provider-neutral lifecycle state used by freshness
// policy. Unknown and unsupported never imply active.
type AccountState string

const (
	AccountStateActive      AccountState = "active"
	AccountStateSuspended   AccountState = "suspended"
	AccountStateDisabled    AccountState = "disabled"
	AccountStatePending     AccountState = "pending"
	AccountStateArchived    AccountState = "archived"
	AccountStateUnknown     AccountState = "unknown"
	AccountStateUnsupported AccountState = "unsupported"
)

func ParseAccountState(value string) (AccountState, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(AccountStateActive):
		return AccountStateActive, nil
	case string(AccountStateSuspended):
		return AccountStateSuspended, nil
	case string(AccountStateDisabled):
		return AccountStateDisabled, nil
	case string(AccountStatePending):
		return AccountStatePending, nil
	case string(AccountStateArchived):
		return AccountStateArchived, nil
	case string(AccountStateUnsupported):
		return AccountStateUnsupported, nil
	case "", string(AccountStateUnknown):
		return AccountStateUnknown, ErrAccountStateUnknown
	default:
		return AccountStateUnknown, ErrAccountStateUnknown
	}
}

func AccountStateFromProvider(state ProviderAccountState) AccountState {
	switch state {
	case ProviderAccountStateActive:
		return AccountStateActive
	case ProviderAccountStateSuspended:
		return AccountStateSuspended
	case ProviderAccountStateDisabled:
		return AccountStateDisabled
	default:
		return AccountStateUnknown
	}
}

func (s AccountState) hardDeny() bool {
	switch s {
	case AccountStateSuspended, AccountStateDisabled, AccountStatePending, AccountStateArchived:
		return true
	default:
		return false
	}
}

type AccountStateObservation struct {
	State      AccountState
	Source     string
	ObservedAt time.Time
}

type AccountStateSource interface {
	ResolveAccountState(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error)
}

type AccountStateSourceFunc func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error)

func (f AccountStateSourceFunc) ResolveAccountState(ctx context.Context, principal AuthenticatedPrincipal) (AccountStateObservation, error) {
	if f == nil {
		return AccountStateObservation{}, ErrAccountStateUnavailable
	}
	return f(ctx, principal)
}

type NamedAccountStateSource struct {
	Name   string
	Source AccountStateSource
}

type AccountStateRequest struct {
	Principal        AuthenticatedPrincipal
	MaximumStaleness time.Duration
	Privileged       bool
}

type AccountStateResolution struct {
	State           AccountState
	ObservedAt      time.Time
	Sources         []AccountStateObservation
	FromCache       bool
	Conflict        bool
	Unavailable     bool
	InvalidEvidence bool
}

func (r AccountStateResolution) clone() AccountStateResolution {
	r.Sources = slices.Clone(r.Sources)
	return r
}

type AccountStateResolver interface {
	ResolveCurrentAccountState(context.Context, AccountStateRequest) (AccountStateResolution, error)
}

type AccountStateInvalidator interface {
	InvalidateAccountState(context.Context, string, string) error
}

type AccountStateScopeInvalidator interface {
	InvalidateAccountStates(context.Context, PermissionInvalidationScope, int) (deleted int, more bool, err error)
}

type CompositeAccountStateResolverConfig struct {
	Sources  []NamedAccountStateSource
	CacheTTL time.Duration
	Now      func() time.Time
}

type accountStateCacheEntry struct {
	resolution AccountStateResolution
	expiresAt  time.Time
}

// CompositeAccountStateResolver evaluates every configured authoritative
// source. Hard denies win; privileged ambiguity and outage fail closed.
type CompositeAccountStateResolver struct {
	sources  []NamedAccountStateSource
	cacheTTL time.Duration
	now      func() time.Time

	mu      sync.RWMutex
	cache   map[string]accountStateCacheEntry
	indexes map[string]map[string]struct{}
	scopes  map[string]PermissionInvalidationScope
}

func NewCompositeAccountStateResolver(cfg CompositeAccountStateResolverConfig) (*CompositeAccountStateResolver, error) {
	if len(cfg.Sources) == 0 || cfg.CacheTTL < 0 {
		return nil, fmt.Errorf("%w: account-state sources and non-negative cache TTL are required", ErrFreshnessPolicyInvalid)
	}
	seen := map[string]struct{}{}
	sources := make([]NamedAccountStateSource, 0, len(cfg.Sources))
	for _, source := range cfg.Sources {
		source.Name = strings.TrimSpace(source.Name)
		if source.Name == "" || source.Source == nil {
			return nil, fmt.Errorf("%w: named account-state source is required", ErrFreshnessPolicyInvalid)
		}
		if _, exists := seen[source.Name]; exists {
			return nil, fmt.Errorf("%w: duplicate account-state source %q", ErrFreshnessPolicyInvalid, source.Name)
		}
		seen[source.Name] = struct{}{}
		sources = append(sources, source)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &CompositeAccountStateResolver{
		sources: sources, cacheTTL: cfg.CacheTTL, now: now,
		cache:   map[string]accountStateCacheEntry{},
		indexes: map[string]map[string]struct{}{},
		scopes:  map[string]PermissionInvalidationScope{},
	}, nil
}

//nolint:gocyclo,funlen // Authoritative-source precedence stays explicit so hard-deny and outage behavior remains auditable.
func (r *CompositeAccountStateResolver) ResolveCurrentAccountState(
	ctx context.Context,
	request AccountStateRequest,
) (AccountStateResolution, error) {
	if r == nil || strings.TrimSpace(request.Principal.ApplicationSubject()) == "" {
		return AccountStateResolution{State: AccountStateUnknown, Unavailable: true}, ErrAccountStateUnavailable
	}
	if request.MaximumStaleness < 0 {
		return AccountStateResolution{State: AccountStateUnknown}, ErrFreshnessPolicyInvalid
	}
	now := r.now()
	key := accountStateCacheKey(request.Principal.ApplicationSubject(), request.Principal.TenantID())
	if request.MaximumStaleness > 0 {
		if cached, ok := r.loadCache(key, now, request.MaximumStaleness); ok {
			cached.FromCache = true
			return cached, accountStateResolutionError(cached, request.Privileged)
		}
	}

	resolution := AccountStateResolution{State: AccountStateUnknown}
	hadError := false
	activeCount := 0
	for _, source := range r.sources {
		observation, err := source.Source.ResolveAccountState(ctx, request.Principal)
		if err != nil {
			hadError = true
			continue
		}
		observation.Source = source.Name
		if observation.ObservedAt.IsZero() {
			observation.ObservedAt = now
		}
		resolution.Sources = append(resolution.Sources, observation)
		if observation.ObservedAt.After(now) {
			resolution.Unavailable = true
			resolution.InvalidEvidence = true
			continue
		}
		if resolution.ObservedAt.IsZero() || observation.ObservedAt.Before(resolution.ObservedAt) {
			resolution.ObservedAt = observation.ObservedAt
		}
		if observation.State.hardDeny() {
			if activeCount > 0 || (resolution.State.hardDeny() && resolution.State != observation.State) {
				resolution.Conflict = true
			}
			resolution.State = observation.State
			continue
		}
		switch observation.State {
		case AccountStateActive:
			activeCount++
			if resolution.State.hardDeny() {
				resolution.Conflict = true
			} else {
				resolution.State = AccountStateActive
			}
		case AccountStateUnknown, AccountStateUnsupported:
			if request.Privileged {
				resolution.Unavailable = true
			}
		default:
			resolution.Unavailable = true
		}
	}
	if hadError || len(resolution.Sources) == 0 {
		resolution.Unavailable = true
	}
	if resolution.State == AccountStateUnknown && activeCount == 0 {
		resolution.Unavailable = true
	}
	if r.cacheTTL > 0 && !resolution.Unavailable && !resolution.Conflict {
		r.storeCache(key, PermissionInvalidationScope{
			ApplicationSubject: request.Principal.ApplicationSubject(),
			TenantID:           request.Principal.TenantID(),
		}, resolution, now.Add(r.cacheTTL))
	}
	return resolution.clone(), accountStateResolutionError(resolution, request.Privileged)
}

func (r *CompositeAccountStateResolver) InvalidateAccountState(_ context.Context, applicationSubject, tenantID string) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.deleteCacheKeyLocked(accountStateCacheKey(applicationSubject, tenantID))
	r.mu.Unlock()
	return nil
}

func (r *CompositeAccountStateResolver) InvalidateAccountStates(
	_ context.Context,
	scope PermissionInvalidationScope,
	limit int,
) (int, bool, error) {
	if r == nil {
		return 0, false, nil
	}
	scope.ApplicationSubject = strings.TrimSpace(scope.ApplicationSubject)
	scope.TenantID = strings.TrimSpace(scope.TenantID)
	scope.SessionID = ""
	labels := permissionInvalidationLabels(scope)
	if len(labels) == 0 || limit <= 0 || limit > 10_000 {
		return 0, false, ErrFreshnessPolicyInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	candidates := r.indexes[permissionInvalidationSelectorLabel(scope)]
	deleted := 0
	inspected := 0
	for key := range candidates {
		if inspected >= limit {
			break
		}
		inspected++
		if !permissionInvalidationScopeMatches(r.scopes[key], scope) {
			delete(candidates, key)
			continue
		}
		r.deleteCacheKeyLocked(key)
		deleted++
	}
	return deleted, len(candidates) > 0, nil
}

func (r *CompositeAccountStateResolver) loadCache(key string, now time.Time, maximumStaleness time.Duration) (AccountStateResolution, bool) {
	r.mu.RLock()
	entry, ok := r.cache[key]
	r.mu.RUnlock()
	if !ok {
		return AccountStateResolution{}, false
	}
	if !now.Before(entry.expiresAt) ||
		entry.resolution.ObservedAt.IsZero() ||
		now.Sub(entry.resolution.ObservedAt) > maximumStaleness {
		r.mu.Lock()
		if current, exists := r.cache[key]; exists && current.expiresAt.Equal(entry.expiresAt) {
			r.deleteCacheKeyLocked(key)
		}
		r.mu.Unlock()
		return AccountStateResolution{}, false
	}
	return entry.resolution.clone(), true
}

func (r *CompositeAccountStateResolver) storeCache(
	key string,
	scope PermissionInvalidationScope,
	resolution AccountStateResolution,
	expiresAt time.Time,
) {
	r.mu.Lock()
	r.removeCacheIndexesLocked(key)
	r.cache[key] = accountStateCacheEntry{resolution: resolution.clone(), expiresAt: expiresAt}
	r.scopes[key] = scope
	for _, label := range permissionInvalidationLabels(scope) {
		keys := r.indexes[label]
		if keys == nil {
			keys = map[string]struct{}{}
			r.indexes[label] = keys
		}
		keys[key] = struct{}{}
	}
	r.mu.Unlock()
}

func (r *CompositeAccountStateResolver) deleteCacheKeyLocked(key string) {
	delete(r.cache, key)
	r.removeCacheIndexesLocked(key)
}

func (r *CompositeAccountStateResolver) removeCacheIndexesLocked(key string) {
	scope, ok := r.scopes[key]
	if !ok {
		return
	}
	for _, label := range permissionInvalidationLabels(scope) {
		keys := r.indexes[label]
		delete(keys, key)
		if len(keys) == 0 {
			delete(r.indexes, label)
		}
	}
	delete(r.scopes, key)
}

func accountStateCacheKey(applicationSubject, tenantID string) string {
	return strings.TrimSpace(applicationSubject) + "\x00" + strings.TrimSpace(tenantID)
}

func accountStateResolutionError(resolution AccountStateResolution, privileged bool) error {
	if resolution.State.hardDeny() {
		switch resolution.State {
		case AccountStateSuspended:
			return ErrUserSuspended
		case AccountStateDisabled:
			return ErrUserDisabled
		case AccountStatePending:
			return ErrUserPending
		case AccountStateArchived:
			return ErrUserArchived
		}
	}
	if resolution.Conflict {
		return ErrAccountStateConflict
	}
	if resolution.InvalidEvidence {
		return ErrAccountStateUnavailable
	}
	if resolution.Unavailable && privileged {
		return ErrAccountStateUnavailable
	}
	if resolution.State != AccountStateActive {
		return ErrAccountStateUnknown
	}
	return nil
}

var _ AccountStateResolver = (*CompositeAccountStateResolver)(nil)
var _ AccountStateInvalidator = (*CompositeAccountStateResolver)(nil)
var _ AccountStateScopeInvalidator = (*CompositeAccountStateResolver)(nil)
