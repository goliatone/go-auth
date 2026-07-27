package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recordingPermissionInvalidator struct {
	mu     sync.Mutex
	calls  int
	scopes []PermissionInvalidationScope
	errs   []error
	more   []bool
}

func (i *recordingPermissionInvalidator) InvalidateScope(
	_ context.Context,
	scope PermissionInvalidationScope,
	_ int,
) (int, bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	index := i.calls
	i.calls++
	i.scopes = append(i.scopes, scope)
	var err error
	if index < len(i.errs) {
		err = i.errs[index]
	}
	var more bool
	if index < len(i.more) {
		more = i.more[index]
	}
	if err != nil {
		return 0, more, err
	}
	return 1, more, nil
}

type recordingAccountInvalidator struct {
	mu    sync.Mutex
	calls int
}

func (i *recordingAccountInvalidator) InvalidateAccountStates(
	context.Context,
	PermissionInvalidationScope,
	int,
) (int, bool, error) {
	i.mu.Lock()
	i.calls++
	i.mu.Unlock()
	return 1, false, nil
}

type recordingSessionInvalidator struct {
	mu     sync.Mutex
	calls  int
	scopes []ProviderSessionInvalidationScope
}

func (i *recordingSessionInvalidator) InvalidateProviderSessions(
	_ context.Context,
	scope ProviderSessionInvalidationScope,
	_ int,
	_ string,
) (int, bool, error) {
	i.mu.Lock()
	i.calls++
	i.scopes = append(i.scopes, scope)
	i.mu.Unlock()
	return 1, false, nil
}

func newTestInvalidationCoordinator(
	t *testing.T,
	permissions PermissionScopeInvalidator,
	accounts AccountStateScopeInvalidator,
	sessions ProviderSessionScopeInvalidator,
) *FreshnessInvalidationCoordinator {
	t.Helper()
	coordinator, err := NewFreshnessInvalidationCoordinator(FreshnessInvalidationCoordinatorConfig{
		Permissions: permissions, AccountStates: accounts, Sessions: sessions,
		BatchLimit: 1, ResultTTL: time.Hour, MaxResults: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func lifecycleFreshnessFixture(action ProviderOperationAction, operationID string) LifecycleFreshnessRequest {
	return LifecycleFreshnessRequest{
		Operation: AuthorizedOperationContext{
			OperationID: operationID,
			Action:      action,
			Target: ProviderOperationTarget{
				Provider: "supabase", ApplicationSubject: "user-1", Subject: "provider-user-1",
			},
			ProviderSessionID: "session-1",
		},
		Remote: ProviderOperationOutcome{Status: ProviderOperationSucceeded},
	}
}

func TestFreshnessInvalidationLifecycleIsIdempotentAndDoesNotRepeatSessionRevocation(t *testing.T) {
	for _, action := range []ProviderOperationAction{
		ProviderActionSuspend, ProviderActionActivate, ProviderActionRemoveFactor,
	} {
		t.Run(string(action), func(t *testing.T) {
			permissions := &recordingPermissionInvalidator{}
			accounts := &recordingAccountInvalidator{}
			sessions := &recordingSessionInvalidator{}
			coordinator := newTestInvalidationCoordinator(t, permissions, accounts, sessions)
			request := lifecycleFreshnessFixture(action, "op-1")

			first, err := coordinator.ConsumeLifecycleResult(context.Background(), request)
			if err != nil || first.PermissionEntries != 1 || first.AccountStateEntries != 1 {
				t.Fatalf("first result=%+v err=%v", first, err)
			}
			second, err := coordinator.ConsumeLifecycleResult(context.Background(), request)
			if err != nil || second != first {
				t.Fatalf("duplicate result=%+v err=%v", second, err)
			}
			if permissions.calls != 1 || accounts.calls != 1 || sessions.calls != 0 {
				t.Fatalf("duplicate or local revocation repeated: permissions=%d accounts=%d sessions=%d",
					permissions.calls, accounts.calls, sessions.calls)
			}
		})
	}
}

func TestFreshnessInvalidationAuthorizationEventCanRevokeScopedSessions(t *testing.T) {
	permissions := &recordingPermissionInvalidator{}
	accounts := &recordingAccountInvalidator{}
	sessions := &recordingSessionInvalidator{}
	coordinator := newTestInvalidationCoordinator(t, permissions, accounts, sessions)
	event := AuthorizationVersionEvent{
		OperationID: "role-change-1", ApplicationSubject: "user-1",
		TenantID: "tenant-1", Version: "42", CommittedAt: time.Now(),
	}
	first, err := coordinator.ConsumeAuthorizationVersion(context.Background(), event, true)
	if err != nil || first.ProviderSessions != 1 {
		t.Fatalf("authorization result=%+v err=%v", first, err)
	}
	_, err = coordinator.ConsumeAuthorizationVersion(context.Background(), event, true)
	if err != nil || permissions.calls != 1 || accounts.calls != 1 || sessions.calls != 1 {
		t.Fatalf("duplicate authorization delivery repeated work: p=%d a=%d s=%d err=%v",
			permissions.calls, accounts.calls, sessions.calls, err)
	}
	if len(sessions.scopes) != 1 ||
		sessions.scopes[0].ApplicationSubject != "user-1" ||
		sessions.scopes[0].TenantID != "tenant-1" ||
		sessions.scopes[0].PermissionVersion != "42" ||
		!sessions.scopes[0].PermissionVersionObservedAt.Equal(event.CommittedAt) {
		t.Fatalf("session scope=%+v", sessions.scopes)
	}
}

func TestFreshnessInvalidationRequiresCommittedTimeForSessionFence(t *testing.T) {
	sessions := &recordingSessionInvalidator{}
	coordinator := newTestInvalidationCoordinator(
		t,
		&recordingPermissionInvalidator{},
		&recordingAccountInvalidator{},
		sessions,
	)
	_, err := coordinator.ConsumeAuthorizationVersion(context.Background(), AuthorizationVersionEvent{
		OperationID:        "missing-commit-time",
		ApplicationSubject: "user-1",
		Version:            "2",
	}, true)
	if !errors.Is(err, ErrFreshnessPolicyInvalid) || sessions.calls != 0 {
		t.Fatalf("missing commit time error=%v session calls=%d", err, sessions.calls)
	}
}

func TestFreshnessInvalidationRetriesPartialAndBoundedWork(t *testing.T) {
	storeErr := errors.New("cache unavailable")
	permissions := &recordingPermissionInvalidator{
		errs: []error{storeErr, nil},
		more: []bool{false, false},
	}
	accounts := &recordingAccountInvalidator{}
	coordinator := newTestInvalidationCoordinator(t, permissions, accounts, nil)
	event := AuthorizationVersionEvent{
		OperationID: "permission-change-1", ApplicationSubject: "user-1", Version: "2",
	}
	first, err := coordinator.ConsumeAuthorizationVersion(context.Background(), event, false)
	if !errors.Is(err, ErrFreshnessInvalidationFailed) || !errors.Is(err, storeErr) ||
		!first.Partial || !first.Retryable {
		t.Fatalf("partial result=%+v err=%v", first, err)
	}
	second, err := coordinator.ConsumeAuthorizationVersion(context.Background(), event, false)
	if err != nil || second.Partial || second.Retryable || permissions.calls != 2 {
		t.Fatalf("retry result=%+v calls=%d err=%v", second, permissions.calls, err)
	}
}

func TestFreshnessInvalidationRejectsOperationIDReuse(t *testing.T) {
	coordinator := newTestInvalidationCoordinator(
		t, &recordingPermissionInvalidator{}, &recordingAccountInvalidator{}, nil,
	)
	event := AuthorizationVersionEvent{
		OperationID: "op-1", ApplicationSubject: "user-1", Version: "1",
	}
	if _, err := coordinator.ConsumeAuthorizationVersion(context.Background(), event, false); err != nil {
		t.Fatal(err)
	}
	event.Version = "2"
	if _, err := coordinator.ConsumeAuthorizationVersion(context.Background(), event, false); !errors.Is(err, ErrProviderOperationConflict) {
		t.Fatalf("operation ID reuse error=%v", err)
	}
}
