package auth

import (
	"context"
	"time"
)

// PermissionCacheStore is the storage contract used by CachedPermissionsResolver.
// The interface is intentionally narrow to align with generic cache backends.
type PermissionCacheStore interface {
	Get(ctx context.Context, key string) (permissions []string, ok bool, err error)
	Set(ctx context.Context, key string, permissions []string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// PurgeablePermissionCacheStore optionally supports active cleanup of expired keys.
// Implementations backed by Redis can ignore this capability.
type PurgeablePermissionCacheStore interface {
	PurgeExpired(ctx context.Context) (purged int, err error)
}

// PermissionInvalidationScope identifies cache entries without requiring
// unbounded key scans. At least one dimension must be present.
type PermissionInvalidationScope struct {
	ApplicationSubject string
	TenantID           string
	SessionID          string
}

// IndexedPermissionCacheStore is the additive bounded-invalidation contract.
type IndexedPermissionCacheStore interface {
	PermissionCacheStore
	IndexPermissionCacheKey(ctx context.Context, key string, scope PermissionInvalidationScope) error
	DeletePermissionCacheScope(ctx context.Context, scope PermissionInvalidationScope, limit int) (deleted int, more bool, err error)
}

// AtomicIndexedPermissionCacheStore publishes a permission value and all of
// its invalidation indexes as one operation. Implementations must leave neither
// the value nor its indexes visible when this method returns an error.
type AtomicIndexedPermissionCacheStore interface {
	IndexedPermissionCacheStore
	SetPermissionCacheEntry(
		ctx context.Context,
		key string,
		permissions []string,
		ttl time.Duration,
		scope PermissionInvalidationScope,
	) error
}

// PermissionCacheErrorMode defines resolver behavior when cache store operations fail.
type PermissionCacheErrorMode string

const (
	// PermissionCacheErrorModeFailOpen bypasses cache errors and continues resolving.
	PermissionCacheErrorModeFailOpen PermissionCacheErrorMode = "fail_open"
	// PermissionCacheErrorModeFailClosed returns cache operation errors immediately.
	PermissionCacheErrorModeFailClosed PermissionCacheErrorMode = "fail_closed"
)

func normalizePermissionCacheErrorMode(mode PermissionCacheErrorMode) PermissionCacheErrorMode {
	switch mode {
	case PermissionCacheErrorModeFailClosed:
		return PermissionCacheErrorModeFailClosed
	case PermissionCacheErrorModeFailOpen:
		return PermissionCacheErrorModeFailOpen
	default:
		return PermissionCacheErrorModeFailOpen
	}
}
