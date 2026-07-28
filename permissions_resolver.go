package auth

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
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

const (
	DefaultPermissionResolutionTimeout = 5 * time.Second
	MaxPermissionResolutionTimeout     = 30 * time.Second
)

// CurrentPermissionsRequest binds permission resolution to the normalized
// principal and authoritative authorization version selected by the freshness
// guard. SessionID is the local provider-session ID when one is available.
type CurrentPermissionsRequest struct {
	Principal AuthenticatedPrincipal
	Version   string
	Role      string
	SessionID string
	// ForceRefresh bypasses every cross-request cache lookup. A successful
	// authoritative result may still replace the entry under the current key.
	ForceRefresh bool
}

type currentPermissionsContextKey struct{}

// WithCurrentPermissionsRequest returns a context whose permission cache keys
// and invalidation scope are derived from current normalized authorization
// state rather than stale token hints.
func WithCurrentPermissionsRequest(
	ctx context.Context,
	request CurrentPermissionsRequest,
) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	request.Principal = request.Principal.Clone()
	request.Version = strings.TrimSpace(request.Version)
	request.Role = strings.TrimSpace(request.Role)
	request.SessionID = strings.TrimSpace(request.SessionID)
	if strings.TrimSpace(request.Principal.ApplicationSubject()) == "" || request.Version == "" {
		return nil, ErrPermissionVersionMissing
	}
	return context.WithValue(ctx, currentPermissionsContextKey{}, request), nil
}

// CurrentPermissionsRequestFromContext returns a defensive copy of the
// authoritative permission-resolution request.
func CurrentPermissionsRequestFromContext(ctx context.Context) (CurrentPermissionsRequest, bool) {
	if ctx == nil {
		return CurrentPermissionsRequest{}, false
	}
	request, ok := ctx.Value(currentPermissionsContextKey{}).(CurrentPermissionsRequest)
	if !ok {
		return CurrentPermissionsRequest{}, false
	}
	request.Principal = request.Principal.Clone()
	return request, true
}

// ResolveCurrentPermissions resolves permissions for an authoritative version.
// Existing PermissionResolverFunc implementations remain source compatible and
// receive the normalized request through context.
func (f PermissionResolverFunc) ResolveCurrentPermissions(
	ctx context.Context,
	request CurrentPermissionsRequest,
) ([]string, error) {
	if f == nil {
		return nil, ErrAuthorizationFreshnessDenied
	}
	currentCtx, err := WithCurrentPermissionsRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	return f(currentCtx)
}

// PermissionCacheKeyFunc computes a stable cache key for a permission resolution request.
// Return ok=false to bypass cross-request caching.
type PermissionCacheKeyFunc func(context.Context) (key string, ok bool)

// CachedPermissionsResolverConfig configures the cross-request resolver cache.
type CachedPermissionsResolverConfig struct {
	Resolver PermissionResolverFunc
	KeyFunc  PermissionCacheKeyFunc
	Store    PermissionCacheStore
	TTL      time.Duration
	// ResolutionTimeout bounds shared backend work independently from any one
	// caller. Zero uses DefaultPermissionResolutionTimeout.
	ResolutionTimeout time.Duration
	CacheErrorMode    PermissionCacheErrorMode
	Logger            Logger
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
	StoreGetErrors     uint64
	StoreSetErrors     uint64
	StoreDeleteErrors  uint64
	PurgeRuns          uint64
	PurgedEntries      uint64
}

// CachedPermissionsResolver wraps a permission resolver with key-based TTL caching
// and singleflight deduplication to prevent query amplification under load.
type CachedPermissionsResolver struct {
	resolver          PermissionResolverFunc
	keyFunc           PermissionCacheKeyFunc
	store             PermissionCacheStore
	ttl               time.Duration
	resolutionTimeout time.Duration
	logger            Logger
	cacheErrorMode    PermissionCacheErrorMode

	group singleflight.Group

	calls              atomic.Uint64
	resolverRuns       atomic.Uint64
	cacheHits          atomic.Uint64
	cacheMisses        atomic.Uint64
	noCacheCalls       atomic.Uint64
	errors             atomic.Uint64
	singleflightShared atomic.Uint64
	storeGetErrors     atomic.Uint64
	storeSetErrors     atomic.Uint64
	storeDeleteErrors  atomic.Uint64
	purgeRuns          atomic.Uint64
	purgedEntries      atomic.Uint64
}

// NewCachedPermissionsResolver builds a CachedPermissionsResolver. When cfg.TTL <= 0,
// cross-request storage is disabled but singleflight deduplication still applies.
func NewCachedPermissionsResolver(cfg CachedPermissionsResolverConfig) *CachedPermissionsResolver {
	keyFn := cfg.KeyFunc
	if keyFn == nil {
		keyFn = DefaultPermissionsCacheKeyFromContext
	}
	store := cfg.Store
	if store == nil {
		store = NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{})
	}
	ttl := max(cfg.TTL, 0)
	resolutionTimeout := cfg.ResolutionTimeout
	if resolutionTimeout <= 0 {
		resolutionTimeout = DefaultPermissionResolutionTimeout
	}
	if resolutionTimeout > MaxPermissionResolutionTimeout {
		resolutionTimeout = MaxPermissionResolutionTimeout
	}
	return &CachedPermissionsResolver{
		resolver:          cfg.Resolver,
		keyFunc:           keyFn,
		store:             store,
		ttl:               ttl,
		resolutionTimeout: resolutionTimeout,
		cacheErrorMode:    normalizePermissionCacheErrorMode(cfg.CacheErrorMode),
		logger:            EnsureLogger(cfg.Logger),
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
	key = strings.TrimSpace(key)
	currentRequest, _ := CurrentPermissionsRequestFromContext(ctx)

	resolve := func() ([]string, error) {
		if currentRequest.ForceRefresh {
			return r.resolveFreshWithCacheKey(ctx, key, ok)
		}
		return r.resolveWithCacheKey(ctx, key, ok)
	}

	if requestCache, hasRequestCache := resolvedPermissionsCacheFromContext(ctx); hasRequestCache {
		return requestCache.resolve(r.requestCacheKey(key, ok, currentRequest.ForceRefresh), resolve)
	}

	return resolve()
}

func (r *CachedPermissionsResolver) resolveWithCacheKey(ctx context.Context, key string, keyOK bool) ([]string, error) {
	if !keyOK || key == "" || r.ttl <= 0 {
		return r.resolveWithoutCache(ctx)
	}

	if cached, hit, err := r.lookup(ctx, key); err != nil {
		return nil, err
	} else if hit {
		r.cacheHits.Add(1)
		return cloneStringSlice(cached), nil
	}
	r.cacheMisses.Add(1)
	resolverBaseCtx := context.WithoutCancel(ctx)
	result := r.group.DoChan(key, func() (any, error) {
		resolverCtx, cancelResolver := context.WithTimeout(
			resolverBaseCtx,
			r.resolutionTimeout,
		)
		defer cancelResolver()
		if cached, hit, lookupErr := r.lookup(resolverCtx, key); lookupErr != nil {
			return nil, lookupErr
		} else if hit {
			return cloneStringSlice(cached), nil
		}
		r.resolverRuns.Add(1)
		perms, resolveErr := r.resolver(resolverCtx)
		if resolveErr != nil {
			r.errors.Add(1)
			return nil, resolveErr
		}
		perms = normalizePermissionValues(perms)
		if storeErr := r.storePermissions(resolverCtx, key, perms); storeErr != nil {
			return nil, storeErr
		}
		return cloneStringSlice(perms), nil
	})

	var flightResult singleflight.Result
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case flightResult = <-result:
	}
	if flightResult.Shared {
		r.singleflightShared.Add(1)
	}
	if flightResult.Err != nil {
		return nil, flightResult.Err
	}
	perms, _ := flightResult.Val.([]string)
	return cloneStringSlice(perms), nil
}

func (r *CachedPermissionsResolver) resolveFreshWithCacheKey(
	ctx context.Context,
	key string,
	keyOK bool,
) ([]string, error) {
	if !keyOK || key == "" || r.ttl <= 0 {
		return r.resolveWithoutCache(ctx)
	}
	r.cacheMisses.Add(1)
	resolverBaseCtx := context.WithoutCancel(ctx)
	result := r.group.DoChan("refresh:"+key, func() (any, error) {
		resolverCtx, cancelResolver := context.WithTimeout(
			resolverBaseCtx,
			r.resolutionTimeout,
		)
		defer cancelResolver()
		r.resolverRuns.Add(1)
		permissions, resolveErr := r.resolver(resolverCtx)
		if resolveErr != nil {
			r.errors.Add(1)
			return nil, resolveErr
		}
		permissions = normalizePermissionValues(permissions)
		if storeErr := r.storePermissions(resolverCtx, key, permissions); storeErr != nil {
			return nil, storeErr
		}
		return cloneStringSlice(permissions), nil
	})

	var flightResult singleflight.Result
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case flightResult = <-result:
	}
	if flightResult.Shared {
		r.singleflightShared.Add(1)
	}
	if flightResult.Err != nil {
		return nil, flightResult.Err
	}
	permissions, _ := flightResult.Val.([]string)
	return cloneStringSlice(permissions), nil
}

func (r *CachedPermissionsResolver) requestCacheKey(
	cacheKey string,
	cacheKeyOK bool,
	forceRefresh bool,
) string {
	if r == nil {
		return ""
	}
	mode := "cached"
	if forceRefresh {
		mode = "refresh"
	}
	if cacheKeyOK && strings.TrimSpace(cacheKey) != "" {
		return fmt.Sprintf("resolver:%p|mode:%s|key:%s", r, mode, cacheKey)
	}
	return fmt.Sprintf("resolver:%p|mode:%s|key:none", r, mode)
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
		StoreGetErrors:     r.storeGetErrors.Load(),
		StoreSetErrors:     r.storeSetErrors.Load(),
		StoreDeleteErrors:  r.storeDeleteErrors.Load(),
		PurgeRuns:          r.purgeRuns.Load(),
		PurgedEntries:      r.purgedEntries.Load(),
	}
}

// Store returns the configured cache store implementation.
func (r *CachedPermissionsResolver) Store() PermissionCacheStore {
	if r == nil {
		return nil
	}
	return r.store
}

// Invalidate removes a single cache key.
func (r *CachedPermissionsResolver) Invalidate(ctx context.Context, key string) error {
	if r == nil || r.store == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	err := r.store.Delete(ctx, key)
	if err == nil {
		return nil
	}
	r.storeDeleteErrors.Add(1)
	r.logCacheStoreError("delete", key, err)
	return err
}

// InvalidateScope removes at most limit indexed entries. Callers retry while
// more=true; no implementation is allowed to fall back to a full key scan.
func (r *CachedPermissionsResolver) InvalidateScope(
	ctx context.Context,
	scope PermissionInvalidationScope,
	limit int,
) (deleted int, more bool, err error) {
	if r == nil || r.store == nil {
		return 0, false, nil
	}
	indexed, ok := r.store.(IndexedPermissionCacheStore)
	if !ok {
		return 0, false, fmt.Errorf("%w: permission cache does not support indexed invalidation", ErrFreshnessPolicyInvalid)
	}
	if limit <= 0 || limit > 10_000 {
		return 0, false, fmt.Errorf("%w: invalid permission invalidation limit", ErrFreshnessPolicyInvalid)
	}
	return indexed.DeletePermissionCacheScope(ctx, scope, limit)
}

// PurgeExpired deletes stale cache entries when the configured store supports it.
func (r *CachedPermissionsResolver) PurgeExpired(ctx context.Context) (int, error) {
	if r == nil || r.store == nil || r.ttl <= 0 {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	purgeable, ok := r.store.(PurgeablePermissionCacheStore)
	if !ok || purgeable == nil {
		return 0, nil
	}
	r.purgeRuns.Add(1)
	purged, err := purgeable.PurgeExpired(ctx)
	if err != nil {
		r.logCacheStoreError("purge", "", err)
		return 0, err
	}
	if purged > 0 {
		r.purgedEntries.Add(uint64(purged))
	}
	return purged, nil
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

func (r *CachedPermissionsResolver) lookup(ctx context.Context, key string) ([]string, bool, error) {
	if r == nil || r.ttl <= 0 || r.store == nil {
		return nil, false, nil
	}
	cached, ok, err := r.store.Get(ctx, key)
	if err != nil {
		r.storeGetErrors.Add(1)
		if r.cacheErrorMode == PermissionCacheErrorModeFailClosed {
			return nil, false, err
		}
		r.logCacheStoreError("get", key, err)
		return nil, false, nil
	}
	if !ok {
		return nil, false, nil
	}
	return normalizePermissionValues(cached), true, nil
}

//nolint:nestif // Scoped cache publication keeps atomicity and fail-open/fail-closed handling together.
func (r *CachedPermissionsResolver) storePermissions(ctx context.Context, key string, permissions []string) error {
	if r == nil || r.ttl <= 0 || r.store == nil {
		return nil
	}
	normalized := normalizePermissionValues(permissions)
	scope := permissionInvalidationScopeFromContext(ctx)
	hasScope := scope.ApplicationSubject != "" || scope.TenantID != "" || scope.SessionID != ""
	if hasScope {
		if atomicStore, ok := r.store.(AtomicIndexedPermissionCacheStore); ok {
			err := atomicStore.SetPermissionCacheEntry(ctx, key, normalized, r.ttl, scope)
			if err == nil {
				return nil
			}
			r.storeSetErrors.Add(1)
			// Defensively remove a value from a custom store that violated the
			// all-or-nothing contract before returning an error.
			_ = r.store.Delete(ctx, key)
			if r.cacheErrorMode == PermissionCacheErrorModeFailClosed {
				return err
			}
			r.logCacheStoreError("set_indexed", key, err)
			return nil
		}
		err := fmt.Errorf(
			"%w: scoped permission cache must publish value and indexes atomically",
			ErrFreshnessPolicyInvalid,
		)
		r.storeSetErrors.Add(1)
		_ = r.store.Delete(ctx, key)
		if r.cacheErrorMode == PermissionCacheErrorModeFailClosed {
			return err
		}
		r.logCacheStoreError("set_indexed", key, err)
		return nil
	}

	err := r.store.Set(ctx, key, normalized, r.ttl)
	if err != nil {
		r.storeSetErrors.Add(1)
		if r.cacheErrorMode == PermissionCacheErrorModeFailClosed {
			return err
		}
		r.logCacheStoreError("set", key, err)
		return nil
	}
	return nil
}

func permissionInvalidationScopeFromContext(ctx context.Context) PermissionInvalidationScope {
	if ctx == nil {
		return PermissionInvalidationScope{}
	}
	claims, hasClaims := GetClaims(ctx)
	parts := permissionCacheKeyParts{}
	parts.applyClaimsIdentity(claims, hasClaims)
	parts.applyActorIdentity(ctx)
	parts.applyActorDiscriminators(ctx)
	parts.applyClaimsDiscriminators(claims, hasClaims)
	parts.applyCurrentPermissionsRequest(ctx)
	return PermissionInvalidationScope{
		ApplicationSubject: strings.TrimSpace(parts.userID),
		TenantID:           strings.TrimSpace(parts.tenantID),
		SessionID:          strings.TrimSpace(parts.sessionID),
	}
}

func (r *CachedPermissionsResolver) logCacheStoreError(operation, key string, err error) {
	if r == nil || err == nil {
		return
	}
	logger := EnsureLogger(r.logger)
	if logger == nil {
		return
	}
	logger.Debug(
		"permission cache store operation failed",
		"operation", operation,
		"key", key,
		"error", err.Error(),
	)
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
	if request, ok := CurrentPermissionsRequestFromContext(ctx); ok {
		return strings.TrimSpace(request.Version)
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

	claims, hasClaims := GetClaims(ctx)
	parts := permissionCacheKeyParts{}
	parts.applyClaimsIdentity(claims, hasClaims)
	parts.applyActorIdentity(ctx)
	parts.applyCurrentPermissionsRequest(ctx)
	if parts.userID == "" {
		return "", false
	}

	parts.applyActorDiscriminators(ctx)
	parts.applyClaimsDiscriminators(claims, hasClaims)
	parts.applyCurrentPermissionsRequest(ctx)

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

	hasDiscriminator := version != "" || tokenID != "" || parts.sessionID != "" || parts.impersonatorID != "" || parts.isImpersonated || scopeMarker != ""
	if !hasDiscriminator {
		return "", false
	}

	keyParts := []string{
		strings.TrimSpace(parts.userID),
		strings.TrimSpace(parts.role),
		strings.TrimSpace(parts.tenantID),
		strings.TrimSpace(parts.orgID),
		strings.TrimSpace(version),
		tokenID,
		parts.impersonatorID,
		strconv.FormatBool(parts.isImpersonated),
		parts.sessionID,
		scopeMarker,
	}
	return composeStableCacheKey(keyParts...), true
}

type permissionCacheKeyParts struct {
	userID         string
	role           string
	tenantID       string
	orgID          string
	impersonatorID string
	isImpersonated bool
	sessionID      string
}

func (p *permissionCacheKeyParts) applyClaimsIdentity(claims AuthClaims, ok bool) {
	if !ok || claims == nil {
		return
	}

	p.userID = strings.TrimSpace(claims.UserID())
	p.role = strings.TrimSpace(claims.Role())
	if carrier, ok := claims.(claimsMetadataCarrier); ok && carrier != nil {
		meta := carrier.ClaimsMetadata()
		p.tenantID = firstMetadataString(meta, tenantMetadataKeys)
		p.orgID = firstMetadataString(meta, organizationMetadataKeys)
	}
}

func (p *permissionCacheKeyParts) applyActorIdentity(ctx context.Context) {
	actor, ok := ActorFromContext(ctx)
	if !ok || actor == nil {
		return
	}

	if p.userID == "" {
		p.userID = firstNonEmptyStrings(strings.TrimSpace(actor.ActorID), strings.TrimSpace(actor.Subject))
	}
	if p.role == "" {
		p.role = strings.TrimSpace(actor.Role)
	}
	if p.tenantID == "" {
		p.tenantID = strings.TrimSpace(actor.TenantID)
	}
	if p.orgID == "" {
		p.orgID = strings.TrimSpace(actor.OrganizationID)
	}
}

func (p *permissionCacheKeyParts) applyActorDiscriminators(ctx context.Context) {
	actor, ok := ActorFromContext(ctx)
	if !ok || actor == nil {
		return
	}

	p.impersonatorID = strings.TrimSpace(actor.ImpersonatorID)
	p.isImpersonated = actor.IsImpersonated || p.impersonatorID != ""
	p.sessionID = firstMetadataString(actor.Metadata, []string{"session_id"})
}

func (p *permissionCacheKeyParts) applyClaimsDiscriminators(claims AuthClaims, ok bool) {
	if !ok || claims == nil {
		return
	}

	carrier, ok := claims.(claimsMetadataCarrier)
	if !ok || carrier == nil {
		return
	}

	meta := carrier.ClaimsMetadata()
	if p.impersonatorID == "" {
		p.impersonatorID = firstMetadataString(meta, impersonatorMetadataKeys)
	}
	if !p.isImpersonated {
		p.isImpersonated = firstMetadataBool(meta, impersonatedFlagKeys) || p.impersonatorID != ""
	}
	if p.sessionID == "" {
		p.sessionID = firstMetadataString(meta, []string{"session_id"})
	}
}

func (p *permissionCacheKeyParts) applyCurrentPermissionsRequest(ctx context.Context) {
	request, ok := CurrentPermissionsRequestFromContext(ctx)
	if !ok {
		return
	}
	p.userID = strings.TrimSpace(request.Principal.ApplicationSubject())
	p.tenantID = strings.TrimSpace(request.Principal.TenantID())
	p.orgID = strings.TrimSpace(request.Principal.OrganizationID())
	if request.Role != "" {
		p.role = request.Role
	}
	if request.SessionID != "" {
		p.sessionID = request.SessionID
	} else {
		p.sessionID = firstNonEmptyStrings(
			strings.TrimSpace(request.Principal.LocalSessionID()),
			strings.TrimSpace(request.Principal.ProviderSessionID()),
		)
	}
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
