package auth

import (
	"context"
	"errors"
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
