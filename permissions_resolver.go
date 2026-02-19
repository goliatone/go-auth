package auth

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// PermissionsVersionMetadataKey is the preferred claim metadata key used to
	// carry permission-set version/etag values across requests.
	PermissionsVersionMetadataKey = "permissions_version"
)

var permissionVersionMetadataKeys = []string{
	PermissionsVersionMetadataKey,
	"permissions_etag",
	"roles_version",
	"roles_etag",
}

// PermissionResolverFunc resolves effective permission keys from a request context.
type PermissionResolverFunc func(context.Context) ([]string, error)

// PermissionCacheKeyFunc computes a stable cache key for a permission resolution request.
// Return ok=false to bypass cross-request caching.
type PermissionCacheKeyFunc func(context.Context) (key string, ok bool)

// CachedPermissionsResolverConfig configures the cross-request resolver cache.
type CachedPermissionsResolverConfig struct {
	Resolver PermissionResolverFunc
	KeyFunc  PermissionCacheKeyFunc
	TTL      time.Duration
	Logger   Logger
}

// PermissionResolverStats exposes lightweight runtime counters for observability.
type PermissionResolverStats struct {
	Calls              uint64
	ResolverRuns       uint64
	CacheHits          uint64
	CacheMisses        uint64
	NoCacheCalls       uint64
	Errors             uint64
	SingleflightShared uint64
}

type cachedPermissionsEntry struct {
	permissions []string
	expiresAt   time.Time
}

// CachedPermissionsResolver wraps a permission resolver with key-based TTL caching
// and singleflight deduplication to prevent query amplification under load.
type CachedPermissionsResolver struct {
	resolver PermissionResolverFunc
	keyFunc  PermissionCacheKeyFunc
	ttl      time.Duration
	logger   Logger
	now      func() time.Time

	group singleflight.Group
	mu    sync.RWMutex
	cache map[string]cachedPermissionsEntry

	calls              atomic.Uint64
	resolverRuns       atomic.Uint64
	cacheHits          atomic.Uint64
	cacheMisses        atomic.Uint64
	noCacheCalls       atomic.Uint64
	errors             atomic.Uint64
	singleflightShared atomic.Uint64
}

// NewCachedPermissionsResolver builds a CachedPermissionsResolver. When cfg.TTL <= 0,
// cross-request storage is disabled but singleflight deduplication still applies.
func NewCachedPermissionsResolver(cfg CachedPermissionsResolverConfig) *CachedPermissionsResolver {
	keyFn := cfg.KeyFunc
	if keyFn == nil {
		keyFn = DefaultPermissionsCacheKeyFromContext
	}
	ttl := cfg.TTL
	if ttl < 0 {
		ttl = 0
	}
	return &CachedPermissionsResolver{
		resolver: cfg.Resolver,
		keyFunc:  keyFn,
		ttl:      ttl,
		logger:   EnsureLogger(cfg.Logger),
		now:      time.Now,
		cache:    map[string]cachedPermissionsEntry{},
	}
}

// ResolverFunc returns the wrapped resolver function.
func (r *CachedPermissionsResolver) ResolverFunc() PermissionResolverFunc {
	if r == nil {
		return nil
	}
	return r.ResolvePermissions
}

// ResolvePermissions resolves permissions with cache + singleflight safeguards.
func (r *CachedPermissionsResolver) ResolvePermissions(ctx context.Context) ([]string, error) {
	if r == nil || r.resolver == nil {
		return nil, nil
	}
	r.calls.Add(1)
	if ctx == nil {
		ctx = context.Background()
	}

	key, ok := r.keyFunc(ctx)
	if !ok || strings.TrimSpace(key) == "" {
		return r.resolveWithoutCache(ctx)
	}
	key = strings.TrimSpace(key)

	if cached, hit := r.lookup(key); hit {
		r.cacheHits.Add(1)
		return cloneStringSlice(cached), nil
	}
	r.cacheMisses.Add(1)

	value, err, shared := r.group.Do(key, func() (any, error) {
		if cached, hit := r.lookup(key); hit {
			return cloneStringSlice(cached), nil
		}
		r.resolverRuns.Add(1)
		perms, resolveErr := r.resolver(ctx)
		if resolveErr != nil {
			r.errors.Add(1)
			return nil, resolveErr
		}
		perms = normalizePermissionValues(perms)
		r.store(key, perms)
		return cloneStringSlice(perms), nil
	})
	if shared {
		r.singleflightShared.Add(1)
	}
	if err != nil {
		return nil, err
	}
	perms, _ := value.([]string)
	return cloneStringSlice(perms), nil
}

// Stats returns a copy of the internal counters.
func (r *CachedPermissionsResolver) Stats() PermissionResolverStats {
	if r == nil {
		return PermissionResolverStats{}
	}
	return PermissionResolverStats{
		Calls:              r.calls.Load(),
		ResolverRuns:       r.resolverRuns.Load(),
		CacheHits:          r.cacheHits.Load(),
		CacheMisses:        r.cacheMisses.Load(),
		NoCacheCalls:       r.noCacheCalls.Load(),
		Errors:             r.errors.Load(),
		SingleflightShared: r.singleflightShared.Load(),
	}
}

// Invalidate removes a single cache key.
func (r *CachedPermissionsResolver) Invalidate(key string) {
	if r == nil {
		return
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	r.mu.Lock()
	delete(r.cache, key)
	r.mu.Unlock()
}

// PurgeExpired deletes stale cache entries.
func (r *CachedPermissionsResolver) PurgeExpired() {
	if r == nil || r.ttl <= 0 {
		return
	}
	now := r.now()
	r.mu.Lock()
	for key, entry := range r.cache {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			delete(r.cache, key)
		}
	}
	r.mu.Unlock()
}

func (r *CachedPermissionsResolver) resolveWithoutCache(ctx context.Context) ([]string, error) {
	r.noCacheCalls.Add(1)
	r.cacheMisses.Add(1)
	r.resolverRuns.Add(1)
	perms, err := r.resolver(ctx)
	if err != nil {
		r.errors.Add(1)
		return nil, err
	}
	return normalizePermissionValues(perms), nil
}

func (r *CachedPermissionsResolver) lookup(key string) ([]string, bool) {
	if r == nil || r.ttl <= 0 {
		return nil, false
	}
	now := r.now()
	r.mu.RLock()
	entry, ok := r.cache[key]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
		r.mu.Lock()
		if current, exists := r.cache[key]; exists && current.expiresAt.Equal(entry.expiresAt) {
			delete(r.cache, key)
		}
		r.mu.Unlock()
		return nil, false
	}
	return entry.permissions, true
}

func (r *CachedPermissionsResolver) store(key string, permissions []string) {
	if r == nil || r.ttl <= 0 {
		return
	}
	expiresAt := r.now().Add(r.ttl)
	r.mu.Lock()
	r.cache[key] = cachedPermissionsEntry{
		permissions: cloneStringSlice(permissions),
		expiresAt:   expiresAt,
	}
	r.mu.Unlock()
}

// SetPermissionsVersionMetadata stores a compact permission-version marker in claims metadata.
func SetPermissionsVersionMetadata(claims *JWTClaims, version string) {
	if claims == nil {
		return
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return
	}
	if claims.Metadata == nil {
		claims.Metadata = map[string]any{}
	}
	claims.Metadata[PermissionsVersionMetadataKey] = version
}

// PermissionsVersionFromClaims extracts the permissions version from claims metadata.
func PermissionsVersionFromClaims(claims AuthClaims) string {
	if claims == nil {
		return ""
	}
	carrier, ok := claims.(claimsMetadataCarrier)
	if !ok || carrier == nil {
		return ""
	}
	return firstMetadataString(carrier.ClaimsMetadata(), permissionVersionMetadataKeys)
}

// PermissionsVersionFromContext extracts the permissions version from actor/claims metadata.
func PermissionsVersionFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if actor, ok := ActorFromContext(ctx); ok && actor != nil {
		if version := firstMetadataString(actor.Metadata, permissionVersionMetadataKeys); version != "" {
			return version
		}
	}
	claims, ok := GetClaims(ctx)
	if !ok {
		return ""
	}
	return PermissionsVersionFromClaims(claims)
}

// DefaultPermissionsCacheKeyFromContext builds a stable resolver key:
// user + role + scope + permissions_version (fallback token_id).
func DefaultPermissionsCacheKeyFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	userID := ""
	role := ""
	tenantID := ""
	orgID := ""

	if claims, ok := GetClaims(ctx); ok && claims != nil {
		userID = strings.TrimSpace(claims.UserID())
		role = strings.TrimSpace(claims.Role())
		if carrier, ok := claims.(claimsMetadataCarrier); ok && carrier != nil {
			meta := carrier.ClaimsMetadata()
			if tenantID == "" {
				tenantID = firstMetadataString(meta, tenantMetadataKeys)
			}
			if orgID == "" {
				orgID = firstMetadataString(meta, organizationMetadataKeys)
			}
		}
	}
	if actor, ok := ActorFromContext(ctx); ok && actor != nil {
		if userID == "" {
			userID = firstNonEmptyStrings(strings.TrimSpace(actor.ActorID), strings.TrimSpace(actor.Subject))
		}
		if role == "" {
			role = strings.TrimSpace(actor.Role)
		}
		if tenantID == "" {
			tenantID = strings.TrimSpace(actor.TenantID)
		}
		if orgID == "" {
			orgID = strings.TrimSpace(actor.OrganizationID)
		}
	}
	if userID == "" {
		return "", false
	}
	version := PermissionsVersionFromContext(ctx)
	if version == "" {
		if tokenID, ok := TokenIDFromContext(ctx); ok {
			version = strings.TrimSpace(tokenID)
		}
	}
	if version == "" {
		version = "none"
	}

	parts := []string{
		strings.ToLower(strings.TrimSpace(userID)),
		strings.ToLower(strings.TrimSpace(role)),
		strings.ToLower(strings.TrimSpace(tenantID)),
		strings.ToLower(strings.TrimSpace(orgID)),
		strings.ToLower(strings.TrimSpace(version)),
	}
	return strings.Join(parts, "|"), true
}

func firstMetadataString(metadata map[string]any, keys []string) string {
	if len(metadata) == 0 || len(keys) == 0 {
		return ""
	}
	for _, key := range keys {
		raw, ok := metadata[key]
		if !ok {
			continue
		}
		if value := metadataValueToString(raw); value != "" {
			return value
		}
	}
	return ""
}

func metadataValueToString(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float64:
		return strings.TrimSpace(strconv.FormatFloat(v, 'f', -1, 64))
	default:
		return ""
	}
}

func normalizePermissionValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func firstNonEmptyStrings(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
