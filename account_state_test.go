package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func accountStatePrincipal(t *testing.T) AuthenticatedPrincipal {
	t.Helper()
	principal, err := NewAuthenticatedPrincipal(AuthenticatedPrincipalInput{
		ApplicationSubject: "user-1",
		Provider:           "supabase",
		ProviderSubject:    "provider-user-1",
		TenantID:           "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func staticAccountStateSource(state AccountState, now time.Time, calls *int) AccountStateSource {
	return AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
		*calls++
		return AccountStateObservation{State: state, ObservedAt: now}, nil
	})
}

func TestCompositeAccountStateResolverPrecedence(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name        string
		states      []AccountState
		expected    AccountState
		expectedErr error
		conflict    bool
	}{
		{name: "active", states: []AccountState{AccountStateActive, AccountStateActive}, expected: AccountStateActive},
		{name: "suspended wins", states: []AccountState{AccountStateActive, AccountStateSuspended}, expected: AccountStateSuspended, expectedErr: ErrUserSuspended, conflict: true},
		{name: "disabled wins", states: []AccountState{AccountStateDisabled, AccountStateActive}, expected: AccountStateDisabled, expectedErr: ErrUserDisabled, conflict: true},
		{name: "pending denies", states: []AccountState{AccountStatePending}, expected: AccountStatePending, expectedErr: ErrUserPending},
		{name: "archived denies", states: []AccountState{AccountStateArchived}, expected: AccountStateArchived, expectedErr: ErrUserArchived},
		{name: "unknown privileged", states: []AccountState{AccountStateUnknown}, expected: AccountStateUnknown, expectedErr: ErrAccountStateUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sources := make([]NamedAccountStateSource, 0, len(tc.states))
			for index, state := range tc.states {
				calls := 0
				sources = append(sources, NamedAccountStateSource{
					Name:   string(rune('a' + index)),
					Source: staticAccountStateSource(state, now, &calls),
				})
			}
			resolver, err := NewCompositeAccountStateResolver(CompositeAccountStateResolverConfig{
				Sources: sources, Now: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := resolver.ResolveCurrentAccountState(context.Background(), AccountStateRequest{
				Principal: accountStatePrincipal(t), Privileged: true,
			})
			if result.State != tc.expected || result.Conflict != tc.conflict || !errors.Is(err, tc.expectedErr) {
				t.Fatalf("result=%+v err=%v; expected state=%q conflict=%t err=%v", result, err, tc.expected, tc.conflict, tc.expectedErr)
			}
		})
	}
}

func TestCompositeAccountStateResolverCacheStalenessAndInvalidation(t *testing.T) {
	now := time.Now().UTC()
	calls := 0
	state := AccountStateActive
	resolver, err := NewCompositeAccountStateResolver(CompositeAccountStateResolverConfig{
		Sources: []NamedAccountStateSource{{
			Name: "provider",
			Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
				calls++
				return AccountStateObservation{State: state, ObservedAt: now}, nil
			}),
		}},
		CacheTTL: time.Minute,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := AccountStateRequest{
		Principal: accountStatePrincipal(t), MaximumStaleness: time.Minute, Privileged: true,
	}
	if _, resolveErr := resolver.ResolveCurrentAccountState(context.Background(), request); resolveErr != nil {
		t.Fatal(resolveErr)
	}
	state = AccountStateSuspended
	cached, err := resolver.ResolveCurrentAccountState(context.Background(), request)
	if err != nil || !cached.FromCache || calls != 1 {
		t.Fatalf("expected bounded cache hit, result=%+v calls=%d err=%v", cached, calls, err)
	}
	now = now.Add(2 * time.Minute)
	fresh, err := resolver.ResolveCurrentAccountState(context.Background(), request)
	if !errors.Is(err, ErrUserSuspended) || fresh.FromCache || fresh.State != AccountStateSuspended || calls != 2 {
		t.Fatalf("expected stale cache refresh, result=%+v calls=%d err=%v", fresh, calls, err)
	}
	state = AccountStateActive
	if invalidateErr := resolver.InvalidateAccountState(context.Background(), "user-1", "tenant-1"); invalidateErr != nil {
		t.Fatal(invalidateErr)
	}
	fresh, err = resolver.ResolveCurrentAccountState(context.Background(), request)
	if err != nil || fresh.State != AccountStateActive || calls != 3 {
		t.Fatalf("expected invalidated active state, result=%+v calls=%d err=%v", fresh, calls, err)
	}
}

func TestCompositeAccountStateResolverPrivilegedOutageFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	resolver, err := NewCompositeAccountStateResolver(CompositeAccountStateResolverConfig{
		Sources: []NamedAccountStateSource{
			{Name: "local", Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
				return AccountStateObservation{State: AccountStateActive, ObservedAt: now}, nil
			})},
			{Name: "provider", Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
				return AccountStateObservation{}, errors.New("provider unavailable")
			})},
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.ResolveCurrentAccountState(context.Background(), AccountStateRequest{
		Principal: accountStatePrincipal(t), Privileged: true,
	})
	if !errors.Is(err, ErrAccountStateUnavailable) || !result.Unavailable {
		t.Fatalf("privileged outage result=%+v err=%v", result, err)
	}
}

func TestCompositeAccountStateResolverRejectsFutureObservation(t *testing.T) {
	now := time.Now().UTC()
	resolver, err := NewCompositeAccountStateResolver(CompositeAccountStateResolverConfig{
		Sources: []NamedAccountStateSource{{
			Name: "provider",
			Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
				return AccountStateObservation{State: AccountStateActive, ObservedAt: now.Add(time.Minute)}, nil
			}),
		}},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.ResolveCurrentAccountState(context.Background(), AccountStateRequest{
		Principal: accountStatePrincipal(t), Privileged: true,
	})
	if !errors.Is(err, ErrAccountStateUnavailable) ||
		!result.Unavailable ||
		!result.InvalidEvidence {
		t.Fatalf("future observation result=%+v err=%v", result, err)
	}
}

func TestCompositeAccountStateResolverRejectsFutureObservationForNormalRead(t *testing.T) {
	now := time.Now().UTC()
	resolver, err := NewCompositeAccountStateResolver(CompositeAccountStateResolverConfig{
		Sources: []NamedAccountStateSource{{
			Name: "provider",
			Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
				return AccountStateObservation{State: AccountStateActive, ObservedAt: now.Add(time.Minute)}, nil
			}),
		}},
		CacheTTL: time.Minute,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.ResolveCurrentAccountState(context.Background(), AccountStateRequest{
		Principal:        accountStatePrincipal(t),
		MaximumStaleness: time.Minute,
		Privileged:       false,
	})
	if !errors.Is(err, ErrAccountStateUnavailable) ||
		result.State != AccountStateUnknown ||
		!result.Unavailable ||
		!result.InvalidEvidence ||
		result.FromCache {
		t.Fatalf("future normal-read result=%+v err=%v", result, err)
	}
}

func TestCompositeAccountStateResolverUsesExactCompositeInvalidationIndex(t *testing.T) {
	now := time.Now().UTC()
	resolver, err := NewCompositeAccountStateResolver(CompositeAccountStateResolverConfig{
		Sources: []NamedAccountStateSource{{
			Name: "local",
			Source: AccountStateSourceFunc(func(context.Context, AuthenticatedPrincipal) (AccountStateObservation, error) {
				return AccountStateObservation{State: AccountStateActive, ObservedAt: now}, nil
			}),
		}},
		CacheTTL: time.Minute,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(subject, tenant string) {
		principal, principalErr := NewAuthenticatedPrincipal(AuthenticatedPrincipalInput{
			ApplicationSubject: subject,
			Provider:           "supabase",
			ProviderSubject:    "provider-" + subject,
			TenantID:           tenant,
		})
		if principalErr != nil {
			t.Fatal(principalErr)
		}
		if _, resolveErr := resolver.ResolveCurrentAccountState(context.Background(), AccountStateRequest{
			Principal: principal, MaximumStaleness: time.Minute,
		}); resolveErr != nil {
			t.Fatal(resolveErr)
		}
	}
	for index := range 100 {
		resolve("user-1", fmt.Sprintf("other-%d", index))
	}
	resolve("user-1", "target")

	selector := PermissionInvalidationScope{ApplicationSubject: "user-1", TenantID: "target"}
	label := permissionInvalidationSelectorLabel(selector)
	if candidates := len(resolver.indexes[label]); candidates != 1 {
		t.Fatalf("exact account-state index candidates=%d, want 1", candidates)
	}
	deleted, more, err := resolver.InvalidateAccountStates(context.Background(), selector, 1)
	if err != nil || deleted != 1 || more {
		t.Fatalf("exact account-state delete: deleted=%d more=%t err=%v", deleted, more, err)
	}
}
