package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestInMemoryPermissionCacheStoreSetGetDelete(t *testing.T) {
	store := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{})

	if err := store.Set(context.Background(), "k1", []string{"admin.translations.export"}, time.Minute); err != nil {
		t.Fatalf("set key: %v", err)
	}
	perms, ok, err := store.Get(context.Background(), "k1")
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if !ok {
		t.Fatalf("expected key to exist")
	}
	if len(perms) != 1 || perms[0] != "admin.translations.export" {
		t.Fatalf("unexpected permissions: %v", perms)
	}

	if err := store.Delete(context.Background(), "k1"); err != nil {
		t.Fatalf("delete key: %v", err)
	}
	if _, ok, err := store.Get(context.Background(), "k1"); err != nil {
		t.Fatalf("get deleted key: %v", err)
	} else if ok {
		t.Fatalf("expected deleted key to be missing")
	}
}

func TestInMemoryPermissionCacheStoreSetRejectsEmptyKey(t *testing.T) {
	store := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{})
	err := store.Set(context.Background(), "   ", []string{"x"}, time.Second)
	if !errors.Is(err, errPermissionCacheKeyEmpty) {
		t.Fatalf("expected empty-key error, got %v", err)
	}
}

func TestInMemoryPermissionCacheStorePublishesValueAndIndexesAtomically(t *testing.T) {
	store := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{})
	scope := PermissionInvalidationScope{
		ApplicationSubject: "user-1",
		TenantID:           "tenant-1",
		SessionID:          "session-1",
	}
	if err := store.SetPermissionCacheEntry(
		context.Background(),
		"atomic-key",
		[]string{"records.read"},
		time.Minute,
		scope,
	); err != nil {
		t.Fatalf("atomic set: %v", err)
	}
	deleted, more, err := store.DeletePermissionCacheScope(
		context.Background(),
		scope,
		10,
	)
	if err != nil || deleted != 1 || more {
		t.Fatalf("atomic invalidate deleted=%d more=%t err=%v", deleted, more, err)
	}
	if _, ok, err := store.Get(context.Background(), "atomic-key"); err != nil || ok {
		t.Fatalf("atomic key survived invalidation: ok=%t err=%v", ok, err)
	}
}

func TestInMemoryPermissionCacheStoreRejectsIndexWithoutValue(t *testing.T) {
	store := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{})
	err := store.IndexPermissionCacheKey(context.Background(), "missing", PermissionInvalidationScope{
		ApplicationSubject: "user-1",
	})
	if !errors.Is(err, errPermissionCacheKeyEmpty) {
		t.Fatalf("missing value index error=%v", err)
	}
}

func TestInMemoryPermissionCacheStorePurgeExpired(t *testing.T) {
	now := time.Now()
	store := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{
		Now: func() time.Time { return now },
	})
	if err := store.Set(context.Background(), "k1", []string{"a"}, 100*time.Millisecond); err != nil {
		t.Fatalf("set key 1: %v", err)
	}
	if err := store.Set(context.Background(), "k2", []string{"b"}, time.Second); err != nil {
		t.Fatalf("set key 2: %v", err)
	}
	now = now.Add(120 * time.Millisecond)
	purged, err := store.PurgeExpired(context.Background())
	if err != nil {
		t.Fatalf("purge expired: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected one purged key, got %d", purged)
	}
	if _, ok, _ := store.Get(context.Background(), "k1"); ok {
		t.Fatalf("expected first key to be gone")
	}
	if _, ok, _ := store.Get(context.Background(), "k2"); !ok {
		t.Fatalf("expected second key to remain")
	}
}

func TestInMemoryPermissionCacheStoreBoundedIndexedInvalidation(t *testing.T) {
	store := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{})
	entries := []struct {
		key   string
		scope PermissionInvalidationScope
	}{
		{key: "u1-t1-s1", scope: PermissionInvalidationScope{ApplicationSubject: "u1", TenantID: "t1", SessionID: "s1"}},
		{key: "u1-t1-s2", scope: PermissionInvalidationScope{ApplicationSubject: "u1", TenantID: "t1", SessionID: "s2"}},
		{key: "u2-t1-s3", scope: PermissionInvalidationScope{ApplicationSubject: "u2", TenantID: "t1", SessionID: "s3"}},
		{key: "u2-t2-s4", scope: PermissionInvalidationScope{ApplicationSubject: "u2", TenantID: "t2", SessionID: "s4"}},
	}
	for _, entry := range entries {
		if err := store.Set(context.Background(), entry.key, []string{"read"}, time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := store.IndexPermissionCacheKey(context.Background(), entry.key, entry.scope); err != nil {
			t.Fatal(err)
		}
	}

	deleted, more, err := store.DeletePermissionCacheScope(
		context.Background(), PermissionInvalidationScope{ApplicationSubject: "u1", TenantID: "t1"}, 1,
	)
	if err != nil || deleted != 1 || !more {
		t.Fatalf("first bounded delete: deleted=%d more=%t err=%v", deleted, more, err)
	}
	deleted, more, err = store.DeletePermissionCacheScope(
		context.Background(), PermissionInvalidationScope{ApplicationSubject: "u1", TenantID: "t1"}, 1,
	)
	if err != nil || deleted != 1 || more {
		t.Fatalf("retry bounded delete: deleted=%d more=%t err=%v", deleted, more, err)
	}
	deleted, more, err = store.DeletePermissionCacheScope(
		context.Background(), PermissionInvalidationScope{SessionID: "s3"}, 10,
	)
	if err != nil || deleted != 1 || more {
		t.Fatalf("session delete: deleted=%d more=%t err=%v", deleted, more, err)
	}
	if _, ok, _ := store.Get(context.Background(), "u2-t2-s4"); !ok {
		t.Fatal("unrelated tenant entry was deleted")
	}
}

func TestInMemoryPermissionCacheStoreUsesExactCompositeInvalidationIndex(t *testing.T) {
	store := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{})
	for index := range 100 {
		key := fmt.Sprintf("u1-other-%d", index)
		scope := PermissionInvalidationScope{
			ApplicationSubject: "u1",
			TenantID:           fmt.Sprintf("other-%d", index),
			SessionID:          fmt.Sprintf("other-session-%d", index),
		}
		if err := store.Set(context.Background(), key, []string{"read"}, time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := store.IndexPermissionCacheKey(context.Background(), key, scope); err != nil {
			t.Fatal(err)
		}
	}
	for index := range 2 {
		key := fmt.Sprintf("target-%d", index)
		scope := PermissionInvalidationScope{
			ApplicationSubject: "u1",
			TenantID:           "target",
			SessionID:          fmt.Sprintf("target-session-%d", index),
		}
		if err := store.Set(context.Background(), key, []string{"read"}, time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := store.IndexPermissionCacheKey(context.Background(), key, scope); err != nil {
			t.Fatal(err)
		}
	}

	selector := PermissionInvalidationScope{ApplicationSubject: "u1", TenantID: "target"}
	label := permissionInvalidationSelectorLabel(selector)
	if candidates := len(store.indexes[label]); candidates != 2 {
		t.Fatalf("exact composite index candidates=%d, want 2", candidates)
	}
	deleted, more, err := store.DeletePermissionCacheScope(context.Background(), selector, 1)
	if err != nil || deleted != 1 || !more {
		t.Fatalf("first exact bounded delete: deleted=%d more=%t err=%v", deleted, more, err)
	}
	deleted, more, err = store.DeletePermissionCacheScope(context.Background(), selector, 1)
	if err != nil || deleted != 1 || more {
		t.Fatalf("second exact bounded delete: deleted=%d more=%t err=%v", deleted, more, err)
	}
}
