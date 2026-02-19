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
