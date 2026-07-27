package auth

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PermissionVersionResult struct {
	Version string
	// Role is the current host-owned authorization role from the same
	// authoritative read as Version. Freshness policy selection must never use
	// a token or request role in its place.
	Role       string
	ObservedAt time.Time
}

type PermissionVersionResolver interface {
	ResolvePermissionVersion(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error)
}

type PermissionVersionResolverFunc func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error)

func (f PermissionVersionResolverFunc) ResolvePermissionVersion(
	ctx context.Context,
	principal AuthenticatedPrincipal,
) (PermissionVersionResult, error) {
	if f == nil {
		return PermissionVersionResult{}, ErrPermissionVersionMissing
	}
	return f(ctx, principal)
}

// AuthorizationMutation is executed inside the host authorization
// transaction that also advances the permission version.
type AuthorizationMutation func(context.Context) error

// AuthorizationVersionStore is the host-owned atomic transaction boundary.
type AuthorizationVersionStore interface {
	CurrentAuthorizationVersion(context.Context, string, string) (PermissionVersionResult, error)
	AdvanceAuthorizationVersion(context.Context, string, string, string, AuthorizationMutation) (PermissionVersionResult, error)
}

type AuthorizationVersionEvent struct {
	OperationID        string
	ApplicationSubject string
	TenantID           string
	Version            string
	CommittedAt        time.Time
}

type AuthorizationVersionPublisher interface {
	PublishAuthorizationVersion(context.Context, AuthorizationVersionEvent) error
}

type AuthorizationVersionPublisherFunc func(context.Context, AuthorizationVersionEvent) error

func (f AuthorizationVersionPublisherFunc) PublishAuthorizationVersion(ctx context.Context, event AuthorizationVersionEvent) error {
	if f == nil {
		return nil
	}
	return f(ctx, event)
}

type AuthorizationVersionWriteResult struct {
	Event     AuthorizationVersionEvent
	Committed bool
	Published bool
}

// AuthorizationVersionWriter publishes only after the store's atomic mutation
// and version advance have committed.
type AuthorizationVersionWriter struct {
	Store     AuthorizationVersionStore
	Publisher AuthorizationVersionPublisher
	Now       func() time.Time
}

func (w AuthorizationVersionWriter) Advance(
	ctx context.Context,
	operationID, applicationSubject, tenantID string,
	mutation AuthorizationMutation,
) (AuthorizationVersionWriteResult, error) {
	operationID = strings.TrimSpace(operationID)
	applicationSubject = strings.TrimSpace(applicationSubject)
	tenantID = strings.TrimSpace(tenantID)
	if w.Store == nil || mutation == nil || operationID == "" || applicationSubject == "" {
		return AuthorizationVersionWriteResult{}, fmt.Errorf("%w: version store, operation, subject, and mutation are required", ErrFreshnessPolicyInvalid)
	}
	current, err := w.Store.AdvanceAuthorizationVersion(ctx, applicationSubject, tenantID, operationID, mutation)
	if err != nil {
		return AuthorizationVersionWriteResult{}, err
	}
	now := time.Now()
	if w.Now != nil {
		now = w.Now()
	}
	if !current.ObservedAt.IsZero() {
		now = current.ObservedAt
	}
	result := AuthorizationVersionWriteResult{
		Event: AuthorizationVersionEvent{
			OperationID:        operationID,
			ApplicationSubject: applicationSubject,
			TenantID:           tenantID,
			Version:            strings.TrimSpace(current.Version),
			CommittedAt:        now,
		},
		Committed: true,
	}
	if result.Event.Version == "" {
		return result, ErrPermissionVersionMissing
	}
	if w.Publisher == nil {
		return result, nil
	}
	if err := w.Publisher.PublishAuthorizationVersion(ctx, result.Event); err != nil {
		return result, err
	}
	result.Published = true
	return result, nil
}

// StorePermissionVersionResolver reads the current host-owned version.
type StorePermissionVersionResolver struct {
	Store AuthorizationVersionStore
}

func (r StorePermissionVersionResolver) ResolvePermissionVersion(
	ctx context.Context,
	principal AuthenticatedPrincipal,
) (PermissionVersionResult, error) {
	if r.Store == nil {
		return PermissionVersionResult{}, ErrPermissionVersionMissing
	}
	result, err := r.Store.CurrentAuthorizationVersion(
		ctx, principal.ApplicationSubject(), principal.TenantID(),
	)
	if err != nil {
		return PermissionVersionResult{}, err
	}
	result.Version = strings.TrimSpace(result.Version)
	if result.Version == "" {
		return PermissionVersionResult{}, ErrPermissionVersionMissing
	}
	return result, nil
}

type inMemoryAuthorizationVersion struct {
	version    int64
	observedAt time.Time
	operations map[string]string
}

// InMemoryAuthorizationVersionStore is a concurrency-safe reference store for
// tests and single-process hosts. Durable hosts should implement the same
// transaction boundary in their authorization database.
type InMemoryAuthorizationVersionStore struct {
	mu       sync.Mutex
	versions map[string]*inMemoryAuthorizationVersion
	now      func() time.Time
}

func NewInMemoryAuthorizationVersionStore(now func() time.Time) *InMemoryAuthorizationVersionStore {
	if now == nil {
		now = time.Now
	}
	return &InMemoryAuthorizationVersionStore{
		versions: map[string]*inMemoryAuthorizationVersion{},
		now:      now,
	}
}

func (s *InMemoryAuthorizationVersionStore) CurrentAuthorizationVersion(
	_ context.Context,
	applicationSubject, tenantID string,
) (PermissionVersionResult, error) {
	if s == nil {
		return PermissionVersionResult{}, ErrPermissionVersionMissing
	}
	key := authorizationVersionKey(applicationSubject, tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.versions[key]
	if current == nil || current.version <= 0 {
		return PermissionVersionResult{}, ErrPermissionVersionMissing
	}
	return PermissionVersionResult{
		Version: strconv.FormatInt(current.version, 10), ObservedAt: current.observedAt,
	}, nil
}

func (s *InMemoryAuthorizationVersionStore) AdvanceAuthorizationVersion(
	ctx context.Context,
	applicationSubject, tenantID, operationID string,
	mutation AuthorizationMutation,
) (PermissionVersionResult, error) {
	if s == nil || mutation == nil {
		return PermissionVersionResult{}, ErrPermissionVersionMissing
	}
	key := authorizationVersionKey(applicationSubject, tenantID)
	operationID = strings.TrimSpace(operationID)
	if key == "\x00" || operationID == "" {
		return PermissionVersionResult{}, ErrFreshnessPolicyInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.versions[key]
	if current != nil {
		if version := current.operations[operationID]; version != "" {
			return PermissionVersionResult{Version: version, ObservedAt: current.observedAt}, nil
		}
	}
	if err := mutation(ctx); err != nil {
		return PermissionVersionResult{}, err
	}
	if current == nil {
		current = &inMemoryAuthorizationVersion{operations: map[string]string{}}
		s.versions[key] = current
	}
	current.version++
	current.observedAt = s.now()
	version := strconv.FormatInt(current.version, 10)
	current.operations[operationID] = version
	return PermissionVersionResult{Version: version, ObservedAt: current.observedAt}, nil
}

func authorizationVersionKey(applicationSubject, tenantID string) string {
	return strings.TrimSpace(applicationSubject) + "\x00" + strings.TrimSpace(tenantID)
}

var _ PermissionVersionResolver = StorePermissionVersionResolver{}
var _ AuthorizationVersionStore = (*InMemoryAuthorizationVersionStore)(nil)
