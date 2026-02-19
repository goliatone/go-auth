package auth

import (
	"context"
	"fmt"
	"sort"
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
	// PurgeInterval controls how often expired entries are opportunistically
	// removed during writes. Zero selects a safe default when caching is enabled.
	PurgeInterval time.Duration
	Logger        Logger
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
	// purgeInterval throttles automatic expired-entry cleanup while storing keys.
	purgeInterval time.Duration
	logger        Logger
	now           func() time.Time

	group singleflight.Group
	mu    sync.RWMutex
	cache map[string]cachedPermissionsEntry
	// lastPurgeUnixNano tracks the last opportunistic purge execution.
	lastPurgeUnixNano atomic.Int64

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
	purgeInterval := cfg.PurgeInterval
	if purgeInterval < 0 {
		purgeInterval = 0
	}
	if ttl > 0 && purgeInterval == 0 {
		purgeInterval = minDuration(ttl, time.Minute)
	}
	return &CachedPermissionsResolver{
		resolver:      cfg.Resolver,
		keyFunc:       keyFn,
		ttl:           ttl,
		purgeInterval: purgeInterval,
		logger:        EnsureLogger(cfg.Logger),
		now:           time.Now,
		cache:         map[string]cachedPermissionsEntry{},
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
	resolverCtx := context.WithoutCancel(ctx)

	value, err, shared := r.group.Do(key, func() (any, error) {
		if cached, hit := r.lookup(key); hit {
			return cloneStringSlice(cached), nil
		}
		r.resolverRuns.Add(1)
		perms, resolveErr := r.resolver(resolverCtx)
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
	r.lastPurgeUnixNano.Store(now.UnixNano())
	r.purgeExpiredAt(now)
}

func (r *CachedPermissionsResolver) purgeExpiredAt(now time.Time) {
	if r == nil || r.ttl <= 0 {
		return
	}
	r.mu.Lock()
	for key, entry := range r.cache {
		if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
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
	if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
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
	now := r.now()
	r.purgeExpiredIfDue(now)
	expiresAt := now.Add(r.ttl)
	r.mu.Lock()
	r.cache[key] = cachedPermissionsEntry{
		permissions: cloneStringSlice(permissions),
		expiresAt:   expiresAt,
	}
	r.mu.Unlock()
}

func (r *CachedPermissionsResolver) purgeExpiredIfDue(now time.Time) {
	if r == nil || r.ttl <= 0 || r.purgeInterval <= 0 {
		return
	}
	nowUnix := now.UnixNano()
	last := r.lastPurgeUnixNano.Load()
	if last != 0 && nowUnix-last < r.purgeInterval.Nanoseconds() {
		return
	}
	if !r.lastPurgeUnixNano.CompareAndSwap(last, nowUnix) {
		return
	}
	r.purgeExpiredAt(now)
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

// DefaultPermissionsCacheKeyFromContext builds a stable resolver key from
// identity/tenant context plus permission-affecting discriminators (version,
// token, scopes, impersonation, session). It bypasses caching when no
// discriminator is available.
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

	impersonatorID := ""
	isImpersonated := false
	sessionID := ""
	if actor, ok := ActorFromContext(ctx); ok && actor != nil {
		impersonatorID = strings.TrimSpace(actor.ImpersonatorID)
		isImpersonated = actor.IsImpersonated || impersonatorID != ""
		if sessionID == "" {
			sessionID = firstMetadataString(actor.Metadata, []string{"session_id"})
		}
	}

	claims, hasClaims := GetClaims(ctx)
	if hasClaims && claims != nil {
		if carrier, ok := claims.(claimsMetadataCarrier); ok && carrier != nil {
			meta := carrier.ClaimsMetadata()
			if impersonatorID == "" {
				impersonatorID = firstMetadataString(meta, impersonatorMetadataKeys)
			}
			if !isImpersonated {
				isImpersonated = firstMetadataBool(meta, impersonatedFlagKeys) || impersonatorID != ""
			}
			if sessionID == "" {
				sessionID = firstMetadataString(meta, []string{"session_id"})
			}
		}
	}

	version := PermissionsVersionFromContext(ctx)
	tokenID := ""
	if tid, ok := TokenIDFromContext(ctx); ok {
		tokenID = strings.TrimSpace(tid)
	}
	scopeSet := scopesFromContext(ctx, claims, hasClaims)
	scopeMarker := ""
	if len(scopeSet) > 0 {
		scopeMarker = strings.Join(scopeSet, ",")
	}

	hasDiscriminator := version != "" || tokenID != "" || sessionID != "" || impersonatorID != "" || isImpersonated || scopeMarker != ""
	if !hasDiscriminator {
		return "", false
	}

	parts := []string{
		strings.TrimSpace(userID),
		strings.TrimSpace(role),
		strings.TrimSpace(tenantID),
		strings.TrimSpace(orgID),
		strings.TrimSpace(version),
		tokenID,
		impersonatorID,
		strconv.FormatBool(isImpersonated),
		sessionID,
		scopeMarker,
	}
	return composeStableCacheKey(parts...), true
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

func firstMetadataBool(metadata map[string]any, keys []string) bool {
	if len(metadata) == 0 || len(keys) == 0 {
		return false
	}
	for _, key := range keys {
		raw, ok := metadata[key]
		if !ok {
			continue
		}
		if value, ok := metadataValueToBool(raw); ok {
			return value
		}
	}
	return false
}

func composeStableCacheKey(parts ...string) string {
	var builder strings.Builder
	builder.WriteString("perm:v2")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		builder.WriteString("|")
		builder.WriteString(strconv.Itoa(len(part)))
		builder.WriteString(":")
		builder.WriteString(part)
	}
	return builder.String()
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

func metadataValueToBool(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		candidate := strings.TrimSpace(strings.ToLower(v))
		switch candidate {
		case "1", "true", "yes", "y", "on":
			return true, true
		case "0", "false", "no", "n", "off":
			return false, true
		default:
			return false, false
		}
	case int:
		return v != 0, true
	case int64:
		return v != 0, true
	case uint64:
		return v != 0, true
	case float64:
		return v != 0, true
	default:
		return false, false
	}
}

func scopesFromContext(ctx context.Context, claims AuthClaims, hasClaims bool) []string {
	candidates := make([]string, 0, 8)

	if hasClaims && claims != nil {
		if jwtClaims, ok := claims.(*JWTClaims); ok && jwtClaims != nil {
			candidates = append(candidates, jwtClaims.Scopes...)
			if len(jwtClaims.Metadata) > 0 {
				candidates = append(candidates, metadataValueToStringList(jwtClaims.Metadata["scope"])...)
				candidates = append(candidates, metadataValueToStringList(jwtClaims.Metadata["scopes"])...)
			}
		}
		if carrier, ok := claims.(claimsMetadataCarrier); ok && carrier != nil {
			meta := carrier.ClaimsMetadata()
			candidates = append(candidates, metadataValueToStringList(meta["scope"])...)
			candidates = append(candidates, metadataValueToStringList(meta["scopes"])...)
		}
	}

	if actor, ok := ActorFromContext(ctx); ok && actor != nil {
		candidates = append(candidates, metadataValueToStringList(actor.Metadata["scope"])...)
		candidates = append(candidates, metadataValueToStringList(actor.Metadata["scopes"])...)
	}

	if len(candidates) == 0 {
		return nil
	}

	seen := map[string]bool{}
	scopes := make([]string, 0, len(candidates))
	for _, scope := range candidates {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if seen[scope] {
			continue
		}
		seen[scope] = true
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 {
		return nil
	}
	sort.Strings(scopes)
	return scopes
}

func metadataValueToStringList(value any) []string {
	switch v := value.(type) {
	case []string:
		return cloneStringSlice(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if item == nil {
				continue
			}
			if asString := metadataValueToString(item); asString != "" {
				out = append(out, asString)
			}
		}
		return out
	case string:
		raw := strings.TrimSpace(v)
		if raw == "" {
			return nil
		}
		return strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == ' '
		})
	default:
		return nil
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

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}
