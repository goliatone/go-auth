package auth

import (
	"context"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"
)

var resolvedPermissionsCacheCtxKey = &contextKey{"resolved_permissions_cache"}

type requestResolvedPermissionsResult struct {
	permissions []string
	err         error
}

type requestResolvedPermissionsCache struct {
	mu      sync.RWMutex
	results map[string]requestResolvedPermissionsResult
	group   singleflight.Group
}

func newRequestResolvedPermissionsCache() *requestResolvedPermissionsCache {
	return &requestResolvedPermissionsCache{
		results: map[string]requestResolvedPermissionsResult{},
	}
}

// WithResolvedPermissionsCache seeds a request-scoped permission resolver cache
// in the provided context. The cache deduplicates repeated permission lookups
// within the same request context.
func WithResolvedPermissionsCache(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if cache, ok := resolvedPermissionsCacheFromContext(ctx); ok && cache != nil {
		return ctx
	}
	return context.WithValue(ctx, resolvedPermissionsCacheCtxKey, newRequestResolvedPermissionsCache())
}

func resolvedPermissionsCacheFromContext(ctx context.Context) (*requestResolvedPermissionsCache, bool) {
	if ctx == nil {
		return nil, false
	}
	raw, ok := ctx.Value(resolvedPermissionsCacheCtxKey).(*requestResolvedPermissionsCache)
	if !ok || raw == nil {
		return nil, false
	}
	return raw, true
}

func (c *requestResolvedPermissionsCache) resolve(key string, fn func() ([]string, error)) ([]string, error) {
	if c == nil || fn == nil {
		return nil, nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return fn()
	}

	if cached, ok := c.get(key); ok {
		return cloneStringSlice(cached.permissions), cached.err
	}

	value, _, _ := c.group.Do(key, func() (any, error) {
		if cached, ok := c.get(key); ok {
			return cached, nil
		}
		perms, err := fn()
		result := requestResolvedPermissionsResult{
			permissions: cloneStringSlice(perms),
			err:         err,
		}
		c.set(key, result)
		return result, nil
	})

	result, _ := value.(requestResolvedPermissionsResult)
	return cloneStringSlice(result.permissions), result.err
}

func (c *requestResolvedPermissionsCache) get(key string) (requestResolvedPermissionsResult, bool) {
	if c == nil {
		return requestResolvedPermissionsResult{}, false
	}
	c.mu.RLock()
	result, ok := c.results[key]
	c.mu.RUnlock()
	return result, ok
}

func (c *requestResolvedPermissionsCache) set(key string, result requestResolvedPermissionsResult) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.results[key] = result
	c.mu.Unlock()
}
