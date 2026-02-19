package auth

import (
	"context"
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
