package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// InMemoryPermissionCacheStoreConfig configures the default in-memory permission cache store.
type InMemoryPermissionCacheStoreConfig struct {
	// PurgeInterval throttles opportunistic cleanup on writes.
	// Zero applies a sensible default.
	PurgeInterval time.Duration
	// Now can be provided in tests to control time.
	Now func() time.Time
}

type inMemoryPermissionEntry struct {
	permissions []string
	expiresAt   time.Time
}

// InMemoryPermissionCacheStore is the default PermissionCacheStore implementation.
type InMemoryPermissionCacheStore struct {
	now           func() time.Time
	purgeInterval time.Duration

	mu      sync.RWMutex
	entries map[string]inMemoryPermissionEntry
	indexes map[string]map[string]struct{}
	scopes  map[string]PermissionInvalidationScope

	lastPurgeUnixNano atomic.Int64
}

var errPermissionCacheKeyEmpty = errors.New("auth permission cache: empty key")

// NewInMemoryPermissionCacheStore builds an in-memory permission cache store.
func NewInMemoryPermissionCacheStore(cfg InMemoryPermissionCacheStoreConfig) *InMemoryPermissionCacheStore {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	purgeInterval := max(cfg.PurgeInterval, 0)
	if purgeInterval == 0 {
		purgeInterval = time.Minute
	}
	return &InMemoryPermissionCacheStore{
		now:           now,
		purgeInterval: purgeInterval,
		entries:       map[string]inMemoryPermissionEntry{},
		indexes:       map[string]map[string]struct{}{},
		scopes:        map[string]PermissionInvalidationScope{},
	}
}

// Get returns cached permissions when the key exists and has not expired.
func (s *InMemoryPermissionCacheStore) Get(_ context.Context, key string) ([]string, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, false, nil
	}
	now := s.now()
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}
	if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
		s.mu.Lock()
		if current, exists := s.entries[key]; exists && current.expiresAt.Equal(entry.expiresAt) {
			s.deleteKeyLocked(key)
		}
		s.mu.Unlock()
		return nil, false, nil
	}
	return cloneStringSlice(entry.permissions), true, nil
}

// Set stores permissions for the provided key and ttl. ttl<=0 removes the key.
func (s *InMemoryPermissionCacheStore) Set(_ context.Context, key string, permissions []string, ttl time.Duration) error {
	if s == nil {
		return nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return errPermissionCacheKeyEmpty
	}
	if ttl <= 0 {
		return s.Delete(context.Background(), key)
	}
	now := s.now()
	s.purgeExpiredIfDue(now)
	s.mu.Lock()
	s.removeIndexesLocked(key)
	s.entries[key] = inMemoryPermissionEntry{
		permissions: cloneStringSlice(permissions),
		expiresAt:   now.Add(ttl),
	}
	s.mu.Unlock()
	return nil
}

// Delete removes a key from the store.
func (s *InMemoryPermissionCacheStore) Delete(_ context.Context, key string) error {
	if s == nil {
		return nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	s.mu.Lock()
	s.deleteKeyLocked(key)
	s.mu.Unlock()
	return nil
}

func (s *InMemoryPermissionCacheStore) IndexPermissionCacheKey(
	_ context.Context,
	key string,
	scope PermissionInvalidationScope,
) error {
	if s == nil {
		return nil
	}
	key = strings.TrimSpace(key)
	scope.ApplicationSubject = strings.TrimSpace(scope.ApplicationSubject)
	scope.TenantID = strings.TrimSpace(scope.TenantID)
	scope.SessionID = strings.TrimSpace(scope.SessionID)
	if key == "" || (scope.ApplicationSubject == "" && scope.TenantID == "" && scope.SessionID == "") {
		return errPermissionCacheKeyEmpty
	}
	s.mu.Lock()
	if _, exists := s.entries[key]; !exists {
		s.mu.Unlock()
		return errPermissionCacheKeyEmpty
	}
	s.removeIndexesLocked(key)
	s.indexKeyLocked(key, scope)
	s.mu.Unlock()
	return nil
}

func (s *InMemoryPermissionCacheStore) SetPermissionCacheEntry(
	_ context.Context,
	key string,
	permissions []string,
	ttl time.Duration,
	scope PermissionInvalidationScope,
) error {
	if s == nil {
		return nil
	}
	key = strings.TrimSpace(key)
	scope.ApplicationSubject = strings.TrimSpace(scope.ApplicationSubject)
	scope.TenantID = strings.TrimSpace(scope.TenantID)
	scope.SessionID = strings.TrimSpace(scope.SessionID)
	if key == "" ||
		(scope.ApplicationSubject == "" && scope.TenantID == "" && scope.SessionID == "") {
		return errPermissionCacheKeyEmpty
	}
	if ttl <= 0 {
		return s.Delete(context.Background(), key)
	}
	now := s.now()
	s.purgeExpiredIfDue(now)
	s.mu.Lock()
	s.removeIndexesLocked(key)
	s.entries[key] = inMemoryPermissionEntry{
		permissions: cloneStringSlice(permissions),
		expiresAt:   now.Add(ttl),
	}
	s.indexKeyLocked(key, scope)
	s.mu.Unlock()
	return nil
}

func (s *InMemoryPermissionCacheStore) DeletePermissionCacheScope(
	_ context.Context,
	scope PermissionInvalidationScope,
	limit int,
) (int, bool, error) {
	if s == nil {
		return 0, false, nil
	}
	scope.ApplicationSubject = strings.TrimSpace(scope.ApplicationSubject)
	scope.TenantID = strings.TrimSpace(scope.TenantID)
	scope.SessionID = strings.TrimSpace(scope.SessionID)
	labels := permissionInvalidationLabels(scope)
	if len(labels) == 0 || limit <= 0 || limit > 10_000 {
		return 0, false, errPermissionCacheKeyEmpty
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidates := s.indexes[permissionInvalidationSelectorLabel(scope)]
	deleted := 0
	inspected := 0
	for key := range candidates {
		if inspected >= limit {
			break
		}
		inspected++
		if !permissionInvalidationScopeMatches(s.scopes[key], scope) {
			// Repair an inconsistent composite index without deleting the
			// underlying entry, and make bounded retry progress.
			delete(candidates, key)
			continue
		}
		s.deleteKeyLocked(key)
		deleted++
	}
	return deleted, len(candidates) > 0, nil
}

// PurgeExpired removes all expired entries and returns the number of keys removed.
func (s *InMemoryPermissionCacheStore) PurgeExpired(_ context.Context) (int, error) {
	if s == nil {
		return 0, nil
	}
	now := s.now()
	s.lastPurgeUnixNano.Store(now.UnixNano())
	return s.purgeExpiredAt(now), nil
}

func (s *InMemoryPermissionCacheStore) purgeExpiredIfDue(now time.Time) {
	if s == nil || s.purgeInterval <= 0 {
		return
	}
	nowUnix := now.UnixNano()
	last := s.lastPurgeUnixNano.Load()
	if last != 0 && nowUnix-last < s.purgeInterval.Nanoseconds() {
		return
	}
	if !s.lastPurgeUnixNano.CompareAndSwap(last, nowUnix) {
		return
	}
	s.purgeExpiredAt(now)
}

func (s *InMemoryPermissionCacheStore) purgeExpiredAt(now time.Time) int {
	if s == nil {
		return 0
	}
	purged := 0
	s.mu.Lock()
	for key, entry := range s.entries {
		if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
			s.deleteKeyLocked(key)
			purged++
		}
	}
	s.mu.Unlock()
	return purged
}

func (s *InMemoryPermissionCacheStore) deleteKeyLocked(key string) {
	delete(s.entries, key)
	s.removeIndexesLocked(key)
}

func (s *InMemoryPermissionCacheStore) removeIndexesLocked(key string) {
	scope, ok := s.scopes[key]
	if !ok {
		return
	}
	for _, label := range permissionInvalidationLabels(scope) {
		keys := s.indexes[label]
		delete(keys, key)
		if len(keys) == 0 {
			delete(s.indexes, label)
		}
	}
	delete(s.scopes, key)
}

func (s *InMemoryPermissionCacheStore) indexKeyLocked(
	key string,
	scope PermissionInvalidationScope,
) {
	s.scopes[key] = scope
	for _, label := range permissionInvalidationLabels(scope) {
		keys := s.indexes[label]
		if keys == nil {
			keys = map[string]struct{}{}
			s.indexes[label] = keys
		}
		keys[key] = struct{}{}
	}
}

func permissionInvalidationLabels(scope PermissionInvalidationScope) []string {
	dimensions := make([]string, 0, 3)
	if scope.ApplicationSubject != "" {
		dimensions = append(dimensions, "u:"+scope.ApplicationSubject)
	}
	if scope.TenantID != "" {
		dimensions = append(dimensions, "t:"+scope.TenantID)
	}
	if scope.SessionID != "" {
		dimensions = append(dimensions, "s:"+scope.SessionID)
	}
	labels := make([]string, 0, (1<<len(dimensions))-1)
	for mask := 1; mask < 1<<len(dimensions); mask++ {
		parts := make([]string, 0, len(dimensions))
		for index, dimension := range dimensions {
			if mask&(1<<index) != 0 {
				parts = append(parts, dimension)
			}
		}
		labels = append(labels, strings.Join(parts, "\x00"))
	}
	return labels
}

func permissionInvalidationSelectorLabel(scope PermissionInvalidationScope) string {
	labels := permissionInvalidationLabels(scope)
	if len(labels) == 0 {
		return ""
	}
	return labels[len(labels)-1]
}

func permissionInvalidationScopeMatches(value, selector PermissionInvalidationScope) bool {
	return (selector.ApplicationSubject == "" || value.ApplicationSubject == selector.ApplicationSubject) &&
		(selector.TenantID == "" || value.TenantID == selector.TenantID) &&
		(selector.SessionID == "" || value.SessionID == selector.SessionID)
}

var _ IndexedPermissionCacheStore = (*InMemoryPermissionCacheStore)(nil)
var _ AtomicIndexedPermissionCacheStore = (*InMemoryPermissionCacheStore)(nil)
