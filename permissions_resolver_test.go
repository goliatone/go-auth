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
	for i := 0; i < workers; i++ {
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

func TestCachedPermissionsResolverWithoutCancelInSingleflight(t *testing.T) {
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

	if errA != nil || errB != nil {
		t.Fatalf("expected shared resolution to ignore caller cancellation, got errA=%v errB=%v", errA, errB)
	}
}

func TestCachedPermissionsResolverPurgesExpiredEntriesOnStore(t *testing.T) {
	var nextKey atomic.Int64
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(context.Context) ([]string, error) {
			return []string{"admin.translations.export"}, nil
		},
		KeyFunc: func(context.Context) (string, bool) {
			return "k-" + strconv.FormatInt(nextKey.Load(), 10), true
		},
		TTL:           20 * time.Millisecond,
		PurgeInterval: 5 * time.Millisecond,
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

	resolver.mu.RLock()
	size := len(resolver.cache)
	_, staleExists := resolver.cache["k-1"]
	resolver.mu.RUnlock()

	if staleExists {
		t.Fatalf("expected stale key to be purged")
	}
	if size == 0 {
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
