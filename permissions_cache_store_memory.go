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
			delete(s.entries, key)
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
	delete(s.entries, key)
	s.mu.Unlock()
	return nil
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
			delete(s.entries, key)
			purged++
		}
	}
	s.mu.Unlock()
	return purged
}
