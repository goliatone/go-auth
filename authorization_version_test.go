package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthorizationVersionWriterCommitRollbackAndPublish(t *testing.T) {
	now := time.Now().UTC()
	store := NewInMemoryAuthorizationVersionStore(func() time.Time { return now })
	var published []AuthorizationVersionEvent
	writer := AuthorizationVersionWriter{
		Store: store,
		Publisher: AuthorizationVersionPublisherFunc(func(_ context.Context, event AuthorizationVersionEvent) error {
			published = append(published, event)
			return nil
		}),
	}

	result, err := writer.Advance(context.Background(), "op-1", "user-1", "tenant-1", func(context.Context) error {
		return nil
	})
	if err != nil || !result.Committed || !result.Published || result.Event.Version != "1" {
		t.Fatalf("commit result=%+v err=%v", result, err)
	}
	if len(published) != 1 || published[0].Version != "1" {
		t.Fatalf("publish events=%+v", published)
	}

	mutationErr := errors.New("rollback")
	_, err = writer.Advance(context.Background(), "op-2", "user-1", "tenant-1", func(context.Context) error {
		return mutationErr
	})
	if !errors.Is(err, mutationErr) {
		t.Fatalf("rollback error=%v", err)
	}
	current, err := store.CurrentAuthorizationVersion(context.Background(), "user-1", "tenant-1")
	if err != nil || current.Version != "1" || len(published) != 1 {
		t.Fatalf("rollback advanced state: current=%+v published=%+v err=%v", current, published, err)
	}
}

func TestAuthorizationVersionWriterPublicationFailureLeavesCurrentVersionAdvanced(t *testing.T) {
	store := NewInMemoryAuthorizationVersionStore(nil)
	publishErr := errors.New("publisher unavailable")
	writer := AuthorizationVersionWriter{
		Store: store,
		Publisher: AuthorizationVersionPublisherFunc(func(context.Context, AuthorizationVersionEvent) error {
			return publishErr
		}),
	}
	result, err := writer.Advance(context.Background(), "op-1", "user-1", "", func(context.Context) error {
		return nil
	})
	if !errors.Is(err, publishErr) || !result.Committed || result.Published {
		t.Fatalf("publication failure result=%+v err=%v", result, err)
	}
	current, currentErr := store.CurrentAuthorizationVersion(context.Background(), "user-1", "")
	if currentErr != nil || current.Version != result.Event.Version {
		t.Fatalf("old version exposed after publication failure: current=%+v err=%v", current, currentErr)
	}
}

func TestAuthorizationVersionStoreConcurrentAndIdempotentAdvancement(t *testing.T) {
	store := NewInMemoryAuthorizationVersionStore(nil)
	var mutations atomic.Int64
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for index := range workers {
		wg.Go(func() {
			_, err := store.AdvanceAuthorizationVersion(
				context.Background(), "user-1", "tenant-1", fmt.Sprintf("op-%d", index),
				func(context.Context) error {
					mutations.Add(1)
					return nil
				},
			)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	current, err := store.CurrentAuthorizationVersion(context.Background(), "user-1", "tenant-1")
	if err != nil || current.Version != "32" || mutations.Load() != workers {
		t.Fatalf("concurrent current=%+v mutations=%d err=%v", current, mutations.Load(), err)
	}

	duplicateMutations := 0
	_, err = store.AdvanceAuthorizationVersion(context.Background(), "user-1", "tenant-1", "op-0", func(context.Context) error {
		duplicateMutations++
		return nil
	})
	if err != nil || duplicateMutations != 0 {
		t.Fatalf("duplicate operation repeated mutation: count=%d err=%v", duplicateMutations, err)
	}
}

func TestStorePermissionVersionResolver(t *testing.T) {
	store := NewInMemoryAuthorizationVersionStore(nil)
	if _, err := store.AdvanceAuthorizationVersion(context.Background(), "user-1", "tenant-1", "op-1", func(context.Context) error {
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	principal := accountStatePrincipal(t)
	result, err := (StorePermissionVersionResolver{Store: store}).ResolvePermissionVersion(context.Background(), principal)
	if err != nil || result.Version != "1" {
		t.Fatalf("resolved version=%+v err=%v", result, err)
	}
}
