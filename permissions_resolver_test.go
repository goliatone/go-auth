package auth

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCachedPermissionsResolverCachesAndDedupes(t *testing.T) {
	var calls atomic.Int64
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			calls.Add(1)
			time.Sleep(20 * time.Millisecond)
			return []string{"admin.translations.export"}, nil
		},
		KeyFunc: func(context.Context) (string, bool) { return "user|scope|v1", true },
		TTL:     150 * time.Millisecond,
	})

	const workers = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			perms, err := resolver.ResolvePermissions(context.Background())
			if err != nil {
				t.Errorf("resolve permissions: %v", err)
				return
			}
			if len(perms) != 1 || perms[0] != "admin.translations.export" {
				t.Errorf("unexpected permissions: %v", perms)
			}
		}()
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("expected a single resolver run via singleflight, got %d", got)
	}
	if _, err := resolver.ResolvePermissions(context.Background()); err != nil {
		t.Fatalf("resolve from cache: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected cached resolution to avoid resolver run, got %d", got)
	}

	time.Sleep(180 * time.Millisecond)
	if _, err := resolver.ResolvePermissions(context.Background()); err != nil {
		t.Fatalf("resolve after ttl: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected ttl expiry to trigger second resolver run, got %d", got)
	}
}

func TestCachedPermissionsResolverStrictModePreservesLegacyCustomKeyWithoutScope(t *testing.T) {
	var calls atomic.Int64
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			calls.Add(1)
			return []string{"records.read"}, nil
		},
		KeyFunc:        func(context.Context) (string, bool) { return "legacy-custom-key", true },
		TTL:            time.Minute,
		CacheErrorMode: PermissionCacheErrorModeFailClosed,
	})
	for range 2 {
		if _, err := resolver.ResolvePermissions(context.Background()); err != nil {
			t.Fatalf("legacy custom-key resolution failed: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("legacy custom-key context did not cache: calls=%d", calls.Load())
	}
}

func TestWithResolvedPermissionsCacheResolvesOncePerContext(t *testing.T) {
	var runs atomic.Int64
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			runs.Add(1)
			return []string{"admin.translations.export"}, nil
		},
		// Force cross-request cache bypass so this test verifies request-scope behavior.
		KeyFunc: func(context.Context) (string, bool) { return "", false },
		TTL:     2 * time.Minute,
	})

	ctx := WithResolvedPermissionsCache(context.Background())
	for range 3 {
		perms, err := resolver.ResolvePermissions(ctx)
		if err != nil {
			t.Fatalf("resolve permissions: %v", err)
		}
		if len(perms) != 1 || perms[0] != "admin.translations.export" {
			t.Fatalf("unexpected permissions: %v", perms)
		}
	}

	if got := runs.Load(); got != 1 {
		t.Fatalf("expected a single resolver run per request context, got %d", got)
	}

	nextCtx := WithResolvedPermissionsCache(context.Background())
	if _, err := resolver.ResolvePermissions(nextCtx); err != nil {
		t.Fatalf("resolve on new context: %v", err)
	}
	if got := runs.Load(); got != 2 {
		t.Fatalf("expected second context to trigger another resolver run, got %d", got)
	}
}

func TestPermissionsVersionMetadataHelpers(t *testing.T) {
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-1", Subject: "user-1"},
		UID:              "user-1",
		UserRole:         "admin",
	}
	SetPermissionsVersionMetadata(claims, "ver-42")

	if got := PermissionsVersionFromClaims(claims); got != "ver-42" {
		t.Fatalf("expected version from claims, got %q", got)
	}

	ctx := WithClaimsContext(context.Background(), claims)
	if got := PermissionsVersionFromContext(ctx); got != "ver-42" {
		t.Fatalf("expected version from context claims, got %q", got)
	}

	key, ok := DefaultPermissionsCacheKeyFromContext(ctx)
	if !ok {
		t.Fatalf("expected cache key")
	}
	if key == "" {
		t.Fatalf("expected non-empty cache key")
	}
}

func TestDefaultPermissionsCacheKeyChangesWhenPermissionsVersionChanges(t *testing.T) {
	baseClaims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-1", Subject: "user-1"},
		UID:              "user-1",
		UserRole:         "admin",
		Metadata: map[string]any{
			PermissionsVersionMetadataKey: "v1",
		},
	}
	otherClaims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-1", Subject: "user-1"},
		UID:              "user-1",
		UserRole:         "admin",
		Metadata: map[string]any{
			PermissionsVersionMetadataKey: "v2",
		},
	}

	keyA, ok := DefaultPermissionsCacheKeyFromContext(WithClaimsContext(context.Background(), baseClaims))
	if !ok || keyA == "" {
		t.Fatalf("expected keyA")
	}
	keyB, ok := DefaultPermissionsCacheKeyFromContext(WithClaimsContext(context.Background(), otherClaims))
	if !ok || keyB == "" {
		t.Fatalf("expected keyB")
	}
	if keyA == keyB {
		t.Fatalf("expected keys to differ when permissions_version changes")
	}
}

func TestDefaultPermissionsCacheKeyFallsBackToTokenID(t *testing.T) {
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-abc", Subject: "actor-1"},
		UID:              "actor-1",
		UserRole:         "member",
		Metadata: map[string]any{
			"tenant_id":       "tenant-1",
			"organization_id": "org-1",
		},
	}
	ctx := WithClaimsContext(context.Background(), claims)
	key, ok := DefaultPermissionsCacheKeyFromContext(ctx)
	if !ok {
		t.Fatalf("expected cache key")
	}
	if key == "" {
		t.Fatalf("expected non-empty cache key")
	}
	if PermissionsVersionFromContext(ctx) != "" {
		t.Fatalf("expected empty explicit permissions version")
	}
}

func TestDefaultPermissionsCacheKeyNoDelimiterCollisions(t *testing.T) {
	ctxA := WithClaimsContext(context.Background(), &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-1"},
		UID:              "ab",
		UserRole:         "c|d",
	})
	ctxB := WithClaimsContext(context.Background(), &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-1"},
		UID:              "ab|c",
		UserRole:         "d",
	})

	keyA, ok := DefaultPermissionsCacheKeyFromContext(ctxA)
	if !ok || keyA == "" {
		t.Fatalf("expected keyA")
	}
	keyB, ok := DefaultPermissionsCacheKeyFromContext(ctxB)
	if !ok || keyB == "" {
		t.Fatalf("expected keyB")
	}
	if keyA == keyB {
		t.Fatalf("expected distinct keys, got same value %q", keyA)
	}
}

func TestDefaultPermissionsCacheKeyPreservesCase(t *testing.T) {
	ctxUpper := WithClaimsContext(context.Background(), &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-1"},
		UID:              "Alice",
		UserRole:         "admin",
	})
	ctxLower := WithClaimsContext(context.Background(), &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-1"},
		UID:              "alice",
		UserRole:         "admin",
	})

	keyUpper, ok := DefaultPermissionsCacheKeyFromContext(ctxUpper)
	if !ok || keyUpper == "" {
		t.Fatalf("expected keyUpper")
	}
	keyLower, ok := DefaultPermissionsCacheKeyFromContext(ctxLower)
	if !ok || keyLower == "" {
		t.Fatalf("expected keyLower")
	}
	if keyUpper == keyLower {
		t.Fatalf("expected case-distinct keys, got same value %q", keyUpper)
	}
}

func TestDefaultPermissionsCacheKeyIncludesScopesAndImpersonation(t *testing.T) {
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-1"},
		UID:              "user-1",
		UserRole:         "admin",
		Scopes:           []string{"admin:write", "admin:read"},
		Metadata: map[string]any{
			"session_id": "sess-1",
		},
	}
	baseCtx := WithClaimsContext(context.Background(), claims)
	baseCtx = WithActorContext(baseCtx, &ActorContext{
		ActorID:        "user-1",
		Role:           "admin",
		ImpersonatorID: "imp-1",
		IsImpersonated: true,
	})

	keyA, ok := DefaultPermissionsCacheKeyFromContext(baseCtx)
	if !ok || keyA == "" {
		t.Fatalf("expected keyA")
	}

	keyB, ok := DefaultPermissionsCacheKeyFromContext(WithClaimsContext(context.Background(), &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "token-1"},
		UID:              "user-1",
		UserRole:         "admin",
		Scopes:           []string{"admin:read"},
		Metadata: map[string]any{
			"session_id": "sess-1",
		},
	}))
	if !ok || keyB == "" {
		t.Fatalf("expected keyB")
	}
	if keyA == keyB {
		t.Fatalf("expected distinct keys when scopes/impersonation differ")
	}
}

func TestDefaultPermissionsCacheKeyBypassesWhenNoDiscriminator(t *testing.T) {
	ctx := WithClaimsContext(context.Background(), &JWTClaims{
		UID:      "user-1",
		UserRole: "admin",
	})
	key, ok := DefaultPermissionsCacheKeyFromContext(ctx)
	if ok || key != "" {
		t.Fatalf("expected cache-key bypass when no version/token/session/scope/impersonation discriminator is present")
	}
}

func TestCachedPermissionsResolverCallerCancellationDoesNotCancelSharedWork(t *testing.T) {
	expected := []string{"admin.translations.export"}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(ctx context.Context) ([]string, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(30 * time.Millisecond):
				return expected, nil
			}
		},
		KeyFunc: func(context.Context) (string, bool) { return "k|shared", true },
		TTL:     200 * time.Millisecond,
	})

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	var errA error
	var errB error
	go func() {
		defer wg.Done()
		_, errA = resolver.ResolvePermissions(canceled)
	}()
	go func() {
		defer wg.Done()
		_, errB = resolver.ResolvePermissions(context.Background())
	}()
	wg.Wait()

	if !errors.Is(errA, context.Canceled) || errB != nil {
		t.Fatalf("caller/shared cancellation errA=%v errB=%v", errA, errB)
	}
}

func TestCachedPermissionsResolverBoundsHungSharedWork(t *testing.T) {
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(ctx context.Context) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		KeyFunc:           func(context.Context) (string, bool) { return "k|hung", true },
		TTL:               time.Minute,
		ResolutionTimeout: 25 * time.Millisecond,
	})

	startedAt := time.Now()
	_, err := resolver.ResolvePermissions(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung resolver error=%v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("hung resolver exceeded bound: %s", elapsed)
	}
}

func TestCachedPermissionsResolverBoundsHungForcedRefreshWork(t *testing.T) {
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(ctx context.Context) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		KeyFunc:           func(context.Context) (string, bool) { return "k|hung-refresh", true },
		TTL:               time.Minute,
		ResolutionTimeout: 25 * time.Millisecond,
	})

	startedAt := time.Now()
	_, err := resolver.resolveFreshWithCacheKey(context.Background(), "k|hung-refresh", true)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung forced refresh error=%v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("hung forced refresh exceeded bound: %s", elapsed)
	}
}

func TestCachedPermissionsResolverForcedRefreshHonorsCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(ctx context.Context) ([]string, error) {
			close(started)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
				return []string{"admin.translations.export"}, nil
			}
		},
		KeyFunc:           func(context.Context) (string, bool) { return "k|refresh-cancel", true },
		TTL:               time.Minute,
		ResolutionTimeout: time.Second,
	})

	callerCtx, cancelCaller := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := resolver.resolveFreshWithCacheKey(callerCtx, "k|refresh-cancel", true)
		result <- err
	}()
	<-started
	cancelCaller()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("forced refresh caller error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("forced refresh caller did not honor cancellation")
	}
	close(release)
}

func TestCachedPermissionsResolverPurgesExpiredEntriesOnStore(t *testing.T) {
	var nextKey atomic.Int64
	store := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{
		PurgeInterval: 5 * time.Millisecond,
	})
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			return []string{"admin.translations.export"}, nil
		},
		KeyFunc: func(context.Context) (string, bool) {
			return "k-" + strconv.FormatInt(nextKey.Load(), 10), true
		},
		Store: store,
		TTL:   20 * time.Millisecond,
	})

	nextKey.Store(1)
	if _, err := resolver.ResolvePermissions(context.Background()); err != nil {
		t.Fatalf("initial resolve: %v", err)
	}

	time.Sleep(30 * time.Millisecond)

	nextKey.Store(2)
	if _, err := resolver.ResolvePermissions(context.Background()); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if _, ok, err := store.Get(context.Background(), "k-1"); err != nil {
		t.Fatalf("get stale key: %v", err)
	} else if ok {
		t.Fatalf("expected stale key to be purged")
	}
	if _, ok, err := store.Get(context.Background(), "k-2"); err != nil {
		t.Fatalf("get fresh key: %v", err)
	} else if !ok {
		t.Fatalf("expected fresh key to remain cached")
	}
}

func TestCachedPermissionsResolverPropagatesResolverErrors(t *testing.T) {
	sentinel := errors.New("resolver-failed")
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			return nil, sentinel
		},
		KeyFunc: func(context.Context) (string, bool) { return "key", true },
		TTL:     100 * time.Millisecond,
	})

	_, err := resolver.ResolvePermissions(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

type testPermissionCacheStore struct {
	getFunc    func(context.Context, string) ([]string, bool, error)
	setFunc    func(context.Context, string, []string, time.Duration) error
	deleteFunc func(context.Context, string) error
	purgeFunc  func(context.Context) (int, error)
}

func (s *testPermissionCacheStore) Get(ctx context.Context, key string) ([]string, bool, error) {
	if s != nil && s.getFunc != nil {
		return s.getFunc(ctx, key)
	}
	return nil, false, nil
}

func (s *testPermissionCacheStore) Set(ctx context.Context, key string, permissions []string, ttl time.Duration) error {
	if s != nil && s.setFunc != nil {
		return s.setFunc(ctx, key, permissions, ttl)
	}
	return nil
}

func (s *testPermissionCacheStore) Delete(ctx context.Context, key string) error {
	if s != nil && s.deleteFunc != nil {
		return s.deleteFunc(ctx, key)
	}
	return nil
}

func (s *testPermissionCacheStore) PurgeExpired(ctx context.Context) (int, error) {
	if s != nil && s.purgeFunc != nil {
		return s.purgeFunc(ctx)
	}
	return 0, nil
}

type testIndexedPermissionCacheStore struct {
	*testPermissionCacheStore
	indexFunc       func(context.Context, string, PermissionInvalidationScope) error
	deleteScopeFunc func(context.Context, PermissionInvalidationScope, int) (int, bool, error)
}

func (s *testIndexedPermissionCacheStore) IndexPermissionCacheKey(
	ctx context.Context,
	key string,
	scope PermissionInvalidationScope,
) error {
	if s != nil && s.indexFunc != nil {
		return s.indexFunc(ctx, key, scope)
	}
	return nil
}

func (s *testIndexedPermissionCacheStore) DeletePermissionCacheScope(
	ctx context.Context,
	scope PermissionInvalidationScope,
	limit int,
) (int, bool, error) {
	if s != nil && s.deleteScopeFunc != nil {
		return s.deleteScopeFunc(ctx, scope, limit)
	}
	return 0, false, nil
}

type testAtomicIndexedPermissionCacheStore struct {
	*testIndexedPermissionCacheStore
	atomicSetFunc func(
		context.Context,
		string,
		[]string,
		time.Duration,
		PermissionInvalidationScope,
	) error
}

func (s *testAtomicIndexedPermissionCacheStore) SetPermissionCacheEntry(
	ctx context.Context,
	key string,
	permissions []string,
	ttl time.Duration,
	scope PermissionInvalidationScope,
) error {
	if s != nil && s.atomicSetFunc != nil {
		return s.atomicSetFunc(ctx, key, permissions, ttl, scope)
	}
	return nil
}

func TestCachedPermissionsResolverUsesInjectedStore(t *testing.T) {
	var getCalls atomic.Int64
	var setCalls atomic.Int64
	store := &testPermissionCacheStore{
		getFunc: func(context.Context, string) ([]string, bool, error) {
			getCalls.Add(1)
			return nil, false, nil
		},
		setFunc: func(context.Context, string, []string, time.Duration) error {
			setCalls.Add(1)
			return nil
		},
	}

	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			return []string{"admin.translations.export"}, nil
		},
		KeyFunc: func(context.Context) (string, bool) { return "key", true },
		Store:   store,
		TTL:     50 * time.Millisecond,
	})
	perms, err := resolver.ResolvePermissions(context.Background())
	if err != nil {
		t.Fatalf("resolve permissions: %v", err)
	}
	if len(perms) != 1 || perms[0] != "admin.translations.export" {
		t.Fatalf("unexpected permissions: %v", perms)
	}
	if getCalls.Load() == 0 {
		t.Fatalf("expected injected store get to be called")
	}
	if setCalls.Load() == 0 {
		t.Fatalf("expected injected store set to be called")
	}
	if resolver.Store() != store {
		t.Fatalf("expected resolver to expose configured store")
	}
}

func TestCachedPermissionsResolverCacheErrorsFailOpenByDefault(t *testing.T) {
	var resolveRuns atomic.Int64
	store := &testPermissionCacheStore{
		getFunc: func(context.Context, string) ([]string, bool, error) {
			return nil, false, errors.New("cache get failed")
		},
		setFunc: func(context.Context, string, []string, time.Duration) error {
			return errors.New("cache set failed")
		},
	}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			resolveRuns.Add(1)
			return []string{"admin.translations.export"}, nil
		},
		KeyFunc: func(context.Context) (string, bool) { return "key", true },
		Store:   store,
		TTL:     30 * time.Millisecond,
	})

	perms, err := resolver.ResolvePermissions(context.Background())
	if err != nil {
		t.Fatalf("expected fail-open behavior, got error: %v", err)
	}
	if len(perms) != 1 {
		t.Fatalf("expected resolved permissions despite cache failures: %v", perms)
	}
	if resolveRuns.Load() != 1 {
		t.Fatalf("expected resolver run once, got %d", resolveRuns.Load())
	}
	stats := resolver.Stats()
	if stats.StoreGetErrors == 0 || stats.StoreSetErrors == 0 {
		t.Fatalf("expected store error counters to increment, got %+v", stats)
	}
}

func TestCachedPermissionsResolverCacheErrorsFailClosed(t *testing.T) {
	store := &testPermissionCacheStore{
		getFunc: func(context.Context, string) ([]string, bool, error) {
			return nil, false, errors.New("cache get failed")
		},
	}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			return []string{"admin.translations.export"}, nil
		},
		KeyFunc:        func(context.Context) (string, bool) { return "key", true },
		Store:          store,
		TTL:            30 * time.Millisecond,
		CacheErrorMode: PermissionCacheErrorModeFailClosed,
	})

	_, err := resolver.ResolvePermissions(context.Background())
	if err == nil {
		t.Fatalf("expected fail-closed cache error")
	}
}

func TestCachedPermissionsResolverAtomicIndexFailureCannotLeaveEntry(t *testing.T) {
	now := time.Now().UTC()
	sentinel := errors.New("atomic index failed")
	backing := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{})
	store := &testAtomicIndexedPermissionCacheStore{
		testIndexedPermissionCacheStore: &testIndexedPermissionCacheStore{
			testPermissionCacheStore: &testPermissionCacheStore{
				getFunc:    backing.Get,
				setFunc:    backing.Set,
				deleteFunc: backing.Delete,
			},
			indexFunc:       backing.IndexPermissionCacheKey,
			deleteScopeFunc: backing.DeletePermissionCacheScope,
		},
		atomicSetFunc: func(
			ctx context.Context,
			key string,
			permissions []string,
			ttl time.Duration,
			_ PermissionInvalidationScope,
		) error {
			if err := backing.Set(ctx, key, permissions, ttl); err != nil {
				return err
			}
			return sentinel
		},
	}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			return []string{"records.read"}, nil
		},
		KeyFunc: func(context.Context) (string, bool) { return "atomic-failure", true },
		Store:   store,
		TTL:     time.Minute,
	})
	permissions, err := resolver.ResolverFunc().ResolveCurrentPermissions(
		context.Background(),
		CurrentPermissionsRequest{
			Principal: freshnessPrincipal(t, "aal1", "1", now),
			Version:   "1",
			Role:      "office",
			SessionID: "session-1",
		},
	)
	if err != nil || len(permissions) != 1 {
		t.Fatalf("fail-open permissions=%v err=%v", permissions, err)
	}
	if _, ok, getErr := backing.Get(context.Background(), "atomic-failure"); getErr != nil || ok {
		t.Fatalf("failed atomic entry remained cached: ok=%t err=%v", ok, getErr)
	}
}

func TestCachedPermissionsResolverBypassesUnsafeIndexedStore(t *testing.T) {
	now := time.Now().UTC()
	var setCalls atomic.Int64
	store := &testIndexedPermissionCacheStore{
		testPermissionCacheStore: &testPermissionCacheStore{
			setFunc: func(context.Context, string, []string, time.Duration) error {
				setCalls.Add(1)
				return nil
			},
		},
	}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			return []string{"records.read"}, nil
		},
		KeyFunc: func(context.Context) (string, bool) { return "unsafe-indexed", true },
		Store:   store,
		TTL:     time.Minute,
	})
	permissions, err := resolver.ResolverFunc().ResolveCurrentPermissions(
		context.Background(),
		CurrentPermissionsRequest{
			Principal: freshnessPrincipal(t, "aal1", "1", now),
			Version:   "1",
			Role:      "office",
			SessionID: "session-1",
		},
	)
	if err != nil || len(permissions) != 1 {
		t.Fatalf("unsafe indexed fail-open permissions=%v err=%v", permissions, err)
	}
	if setCalls.Load() != 0 {
		t.Fatalf("unsafe indexed store received %d non-atomic writes", setCalls.Load())
	}
	if resolver.Stats().StoreSetErrors != 1 {
		t.Fatalf("unsafe indexed store error was not counted: %+v", resolver.Stats())
	}
}

func TestCachedPermissionsResolverBypassesUnindexedScopedStore(t *testing.T) {
	now := time.Now().UTC()
	var setCalls atomic.Int64
	store := &testPermissionCacheStore{
		setFunc: func(context.Context, string, []string, time.Duration) error {
			setCalls.Add(1)
			return nil
		},
	}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			return []string{"records.read"}, nil
		},
		KeyFunc: func(context.Context) (string, bool) { return "unsafe-unindexed", true },
		Store:   store,
		TTL:     time.Minute,
	})
	permissions, err := resolver.ResolverFunc().ResolveCurrentPermissions(
		context.Background(),
		CurrentPermissionsRequest{
			Principal: freshnessPrincipal(t, "aal1", "1", now),
			Version:   "1",
			Role:      "office",
			SessionID: "session-1",
		},
	)
	if err != nil || len(permissions) != 1 {
		t.Fatalf("unindexed fail-open permissions=%v err=%v", permissions, err)
	}
	if setCalls.Load() != 0 {
		t.Fatalf("unindexed scoped store received %d unreachable writes", setCalls.Load())
	}
	if resolver.Stats().StoreSetErrors != 1 {
		t.Fatalf("unindexed scoped store error was not counted: %+v", resolver.Stats())
	}
}

func TestCachedPermissionsResolverPurgeExpiredDelegatesToStore(t *testing.T) {
	store := &testPermissionCacheStore{
		purgeFunc: func(context.Context) (int, error) {
			return 3, nil
		},
	}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			return []string{"admin.translations.export"}, nil
		},
		KeyFunc: func(context.Context) (string, bool) { return "key", true },
		Store:   store,
		TTL:     30 * time.Millisecond,
	})
	purged, err := resolver.PurgeExpired(context.Background())
	if err != nil {
		t.Fatalf("purge expired: %v", err)
	}
	if purged != 3 {
		t.Fatalf("expected 3 purged entries, got %d", purged)
	}
	stats := resolver.Stats()
	if stats.PurgeRuns != 1 || stats.PurgedEntries != 3 {
		t.Fatalf("unexpected purge stats: %+v", stats)
	}
}

func TestCachedPermissionsResolverInvalidateDelegatesToStore(t *testing.T) {
	var deletedKey atomic.Value
	store := &testPermissionCacheStore{
		deleteFunc: func(_ context.Context, key string) error {
			deletedKey.Store(key)
			return nil
		},
	}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) { return []string{"x"}, nil },
		Store:    store,
		TTL:      time.Minute,
	})
	if err := resolver.Invalidate(context.Background(), "k-1"); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	got, _ := deletedKey.Load().(string)
	if got != "k-1" {
		t.Fatalf("expected deleted key k-1, got %q", got)
	}
}

func TestCachedPermissionsResolverInvalidateReturnsStoreError(t *testing.T) {
	sentinel := errors.New("delete failed")
	store := &testPermissionCacheStore{
		deleteFunc: func(context.Context, string) error {
			return sentinel
		},
	}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) { return []string{"x"}, nil },
		Store:    store,
		TTL:      time.Minute,
	})
	err := resolver.Invalidate(context.Background(), "k-1")
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected delete error, got %v", err)
	}
	stats := resolver.Stats()
	if stats.StoreDeleteErrors != 1 {
		t.Fatalf("expected delete error counter to increment, got %+v", stats)
	}
}

func TestCachedPermissionsResolverPurgeExpiredReturnsStoreError(t *testing.T) {
	sentinel := errors.New("purge failed")
	store := &testPermissionCacheStore{
		purgeFunc: func(context.Context) (int, error) {
			return 0, sentinel
		},
	}
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) { return []string{"x"}, nil },
		Store:    store,
		TTL:      time.Minute,
	})
	_, err := resolver.PurgeExpired(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected purge error, got %v", err)
	}
}
