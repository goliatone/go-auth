package auth

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func freshnessPrincipal(t *testing.T, assurance, version string, now time.Time) AuthenticatedPrincipal {
	t.Helper()
	principal, err := NewAuthenticatedPrincipal(AuthenticatedPrincipalInput{
		ApplicationSubject: "user-1",
		Provider:           "supabase",
		ProviderSubject:    "provider-user-1",
		ProviderSessionID:  "provider-session-1",
		LocalSessionID:     "local-session-1",
		AssuranceLevel:     assurance,
		AssuranceMethods:   []string{"password", "totp"},
		AuthenticationAt:   now.Add(-time.Minute),
		ExpiresAt:          now.Add(time.Hour),
		TenantID:           "tenant-1",
		PermissionVersion:  version,
	})
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func freshnessContext(t *testing.T, principal AuthenticatedPrincipal, now time.Time) context.Context {
	t.Helper()
	return WithProviderSessionContext(context.Background(), ProviderSession{
		ID: "session-1", Status: ProviderSessionAvailable,
		IdleExpiresAt: now.Add(time.Hour), MaxExpiresAt: now.Add(2 * time.Hour),
	}, principal)
}

func newTestFreshnessGuard(
	t *testing.T,
	now time.Time,
	account AccountStateResolver,
	version PermissionVersionResolver,
	permissions PermissionResolverFunc,
) *AuthorizationFreshnessGuard {
	t.Helper()
	policy, err := NewFreshnessPolicy(validFreshnessPolicyConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewAuthorizationFreshnessGuard(AuthorizationFreshnessGuardConfig{
		Policy: policy, AccountStates: account, PermissionVersions: version,
		Permissions: permissions, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func activeAccountResolver(now time.Time) AccountStateResolver {
	return accountStateResolverFunc(func(context.Context, AccountStateRequest) (AccountStateResolution, error) {
		return AccountStateResolution{State: AccountStateActive, ObservedAt: now}, nil
	})
}

type accountStateResolverFunc func(context.Context, AccountStateRequest) (AccountStateResolution, error)

func (f accountStateResolverFunc) ResolveCurrentAccountState(ctx context.Context, request AccountStateRequest) (AccountStateResolution, error) {
	return f(ctx, request)
}

func TestAuthorizationFreshnessGuardAllowsCurrentAuthorizedRequest(t *testing.T) {
	now := time.Now().UTC()
	guard := newTestFreshnessGuard(
		t, now, activeAccountResolver(now),
		PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
			return PermissionVersionResult{Version: "1", Role: "admin", ObservedAt: now}, nil
		}),
		func(context.Context) ([]string, error) { return []string{"provider.account.suspend"}, nil },
	)
	result, err := guard.Authorize(
		freshnessContext(t, freshnessPrincipal(t, "aal2", "1", now), now),
		AuthorizationFreshnessRequest{Operation: "provider.account.suspend", Role: "admin"},
	)
	if err != nil || result.Decision != FreshnessAllowed || result.PermissionsRefreshed {
		t.Fatalf("allowed result=%+v err=%v", result, err)
	}
}

func TestAuthorizationFreshnessGuardRefreshesPermissionMismatch(t *testing.T) {
	now := time.Now().UTC()
	guard := newTestFreshnessGuard(
		t, now, activeAccountResolver(now),
		PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
			return PermissionVersionResult{Version: "2", Role: "admin", ObservedAt: now}, nil
		}),
		func(context.Context) ([]string, error) { return []string{"provider.account.suspend"}, nil },
	)
	result, err := guard.Authorize(
		freshnessContext(t, freshnessPrincipal(t, "aal2", "1", now), now),
		AuthorizationFreshnessRequest{Operation: "provider.account.suspend", Role: "admin"},
	)
	if err != nil || result.Decision != FreshnessAllowed || !result.PermissionsRefreshed || result.CurrentVersion != "2" {
		t.Fatalf("refreshed result=%+v err=%v", result, err)
	}
}

func TestAuthorizationFreshnessGuardMismatchCannotUseOldPermissionCache(t *testing.T) {
	now := time.Now().UTC()
	currentPermissions := []string{"provider.account.suspend"}
	resolverRuns := 0
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(ctx context.Context) ([]string, error) {
			resolverRuns++
			request, ok := CurrentPermissionsRequestFromContext(ctx)
			if resolverRuns > 1 && (!ok || request.Version != "2" ||
				request.Principal.ApplicationSubject() != "user-1" ||
				request.Principal.TenantID() != "tenant-1" ||
				request.SessionID != "session-1" ||
				!request.ForceRefresh) {
				t.Fatalf("current permission request=%+v ok=%t", request, ok)
			}
			return currentPermissions, nil
		},
		KeyFunc: func(context.Context) (string, bool) {
			return "custom-shared-key", true
		},
		TTL: time.Hour,
	})
	oldClaims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-1",
			ID:      "token-1",
		},
		UID:      "user-1",
		UserRole: "admin",
		Metadata: map[string]any{
			PermissionsVersionMetadataKey: "1",
			"tenant_id":                   "tenant-1",
			"session_id":                  "session-1",
		},
	}
	oldCtx := WithClaimsContext(context.Background(), oldClaims)
	if permissions, err := resolver.ResolvePermissions(oldCtx); err != nil ||
		!slices.Contains(permissions, "provider.account.suspend") {
		t.Fatalf("seed old permissions=%v err=%v", permissions, err)
	}
	currentPermissions = []string{"records.read"}

	principal := freshnessPrincipal(t, "aal2", "1", now)
	ctx := WithClaimsContext(freshnessContext(t, principal, now), oldClaims)
	guard := newTestFreshnessGuard(
		t, now, activeAccountResolver(now),
		PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
			return PermissionVersionResult{Version: "2", Role: "admin", ObservedAt: now}, nil
		}),
		resolver.ResolverFunc(),
	)
	result, err := guard.Authorize(ctx, AuthorizationFreshnessRequest{
		Operation: "provider.account.suspend",
		Role:      "admin",
	})
	if !errors.Is(err, ErrAuthorizationFreshnessDenied) ||
		result.Decision != FreshnessDenied ||
		!result.PermissionsRefreshed ||
		resolverRuns != 2 {
		t.Fatalf("result=%+v resolverRuns=%d err=%v", result, resolverRuns, err)
	}
}

func TestAuthorizationFreshnessGuardDenialMatrix(t *testing.T) {
	now := time.Now().UTC()
	baseVersion := PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
		return PermissionVersionResult{Version: "1", Role: "admin", ObservedAt: now}, nil
	})
	basePermissions := PermissionResolverFunc(func(context.Context) ([]string, error) {
		return []string{"provider.account.suspend"}, nil
	})
	tests := []struct {
		name        string
		ctx         func() context.Context
		operation   string
		account     AccountStateResolver
		version     PermissionVersionResolver
		permissions PermissionResolverFunc
		expected    error
		decision    FreshnessDecision
	}{
		{
			name:      "unknown operation",
			ctx:       func() context.Context { return freshnessContext(t, freshnessPrincipal(t, "aal2", "1", now), now) },
			operation: "unknown",
			account:   activeAccountResolver(now), version: baseVersion, permissions: basePermissions,
			expected: ErrFreshnessPolicyInvalid, decision: FreshnessDenied,
		},
		{
			name:      "step up",
			ctx:       func() context.Context { return freshnessContext(t, freshnessPrincipal(t, "aal1", "1", now), now) },
			operation: "provider.account.suspend",
			account:   activeAccountResolver(now), version: baseVersion, permissions: basePermissions,
			expected: ErrAssuranceStepUpRequired, decision: FreshnessStepUp,
		},
		{
			name:      "suspension",
			ctx:       func() context.Context { return freshnessContext(t, freshnessPrincipal(t, "aal2", "1", now), now) },
			operation: "provider.account.suspend",
			account: accountStateResolverFunc(func(context.Context, AccountStateRequest) (AccountStateResolution, error) {
				return AccountStateResolution{State: AccountStateSuspended}, ErrUserSuspended
			}),
			version: baseVersion, permissions: basePermissions,
			expected: ErrUserSuspended, decision: FreshnessDenied,
		},
		{
			name:      "permission denied",
			ctx:       func() context.Context { return freshnessContext(t, freshnessPrincipal(t, "aal2", "1", now), now) },
			operation: "provider.account.suspend",
			account:   activeAccountResolver(now), version: baseVersion,
			permissions: func(context.Context) ([]string, error) { return []string{"records.read"}, nil },
			expected:    ErrAuthorizationFreshnessDenied, decision: FreshnessDenied,
		},
		{
			name:      "version outage",
			ctx:       func() context.Context { return freshnessContext(t, freshnessPrincipal(t, "aal2", "1", now), now) },
			operation: "provider.account.suspend",
			account:   activeAccountResolver(now),
			version: PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
				return PermissionVersionResult{}, ErrPermissionVersionMissing
			}),
			permissions: basePermissions,
			expected:    ErrPermissionVersionMissing, decision: FreshnessDenied,
		},
		{
			name: "revoked provider session",
			ctx: func() context.Context {
				ctx := freshnessContext(t, freshnessPrincipal(t, "aal2", "1", now), now)
				value, _ := ProviderSessionFromContext(ctx)
				value.Session.Status = ProviderSessionRevoked
				return WithProviderSessionContext(context.Background(), value.Session, value.Principal)
			},
			operation: "provider.account.suspend",
			account:   activeAccountResolver(now), version: baseVersion, permissions: basePermissions,
			expected: ErrProviderSessionRevoked, decision: FreshnessDenied,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			guard := newTestFreshnessGuard(t, now, tc.account, tc.version, tc.permissions)
			result, err := guard.Authorize(tc.ctx(), AuthorizationFreshnessRequest{Operation: tc.operation, Role: "admin"})
			if result.Decision != tc.decision || !errors.Is(err, tc.expected) {
				t.Fatalf("result=%+v err=%v; want decision=%q error=%v", result, err, tc.decision, tc.expected)
			}
		})
	}
}

func TestAuthorizationFreshnessGuardNormalReadAcceptsExplicitPrincipal(t *testing.T) {
	now := time.Now().UTC()
	guard := newTestFreshnessGuard(
		t, now, activeAccountResolver(now),
		PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
			return PermissionVersionResult{Version: "1", Role: "office", ObservedAt: now}, nil
		}),
		func(context.Context) ([]string, error) { return []string{"records.read"}, nil },
	)
	result, err := guard.Authorize(context.Background(), AuthorizationFreshnessRequest{
		Operation: "records.read", Role: "office", Principal: freshnessPrincipal(t, "aal1", "1", now),
	})
	if err != nil || result.Decision != FreshnessAllowed {
		t.Fatalf("normal read result=%+v err=%v", result, err)
	}
}

func TestAuthorizationFreshnessGuardUsesAuthoritativeRoleForPolicy(t *testing.T) {
	now := time.Now().UTC()
	guard := newTestFreshnessGuard(
		t, now, activeAccountResolver(now),
		PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
			return PermissionVersionResult{Version: "1", Role: "field", ObservedAt: now}, nil
		}),
		func(context.Context) ([]string, error) { return []string{"records.read"}, nil },
	)

	result, err := guard.Authorize(context.Background(), AuthorizationFreshnessRequest{
		Operation: "records.read",
		Role:      "office",
		Principal: freshnessPrincipal(t, "aal1", "1", now),
	})
	if !errors.Is(err, ErrAssuranceInsufficient) ||
		result.Decision != FreshnessDenied ||
		result.CurrentRole != "field" ||
		result.Policy.RequiredAssurance != AssuranceAAL2 {
		t.Fatalf("authoritative role result=%+v err=%v", result, err)
	}
}

func TestAuthorizationFreshnessGuardPassesAuthoritativeRoleToPermissions(t *testing.T) {
	now := time.Now().UTC()
	var resolvedRole string
	guard := newTestFreshnessGuard(
		t, now, activeAccountResolver(now),
		PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
			return PermissionVersionResult{Version: "1", Role: "field", ObservedAt: now}, nil
		}),
		func(ctx context.Context) ([]string, error) {
			request, ok := CurrentPermissionsRequestFromContext(ctx)
			if !ok {
				t.Fatal("current permission request is missing")
			}
			resolvedRole = request.Role
			return []string{"records.read"}, nil
		},
	)

	result, err := guard.Authorize(context.Background(), AuthorizationFreshnessRequest{
		Operation: "records.read",
		Role:      "office",
		Principal: freshnessPrincipal(t, "aal2", "1", now),
	})
	if err != nil || result.Decision != FreshnessAllowed || resolvedRole != "field" {
		t.Fatalf("authoritative permission role=%q result=%+v err=%v", resolvedRole, result, err)
	}
}

func TestAuthorizationFreshnessGuardRejectsMissingAuthoritativeRole(t *testing.T) {
	now := time.Now().UTC()
	guard := newTestFreshnessGuard(
		t, now, activeAccountResolver(now),
		PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
			return PermissionVersionResult{Version: "1", ObservedAt: now}, nil
		}),
		func(context.Context) ([]string, error) { return []string{"records.read"}, nil },
	)

	result, err := guard.Authorize(context.Background(), AuthorizationFreshnessRequest{
		Operation: "records.read",
		Role:      "office",
		Principal: freshnessPrincipal(t, "aal1", "1", now),
	})
	if !errors.Is(err, ErrAuthorizationRoleMissing) ||
		result.Decision != FreshnessDenied ||
		result.Reason != FreshnessReasonDependencyOutage {
		t.Fatalf("missing role result=%+v err=%v", result, err)
	}
}

func TestAuthorizationFreshnessGuardExplicitPrincipalIndexesCurrentPermissionScope(t *testing.T) {
	now := time.Now().UTC()
	store := NewInMemoryPermissionCacheStore(InMemoryPermissionCacheStoreConfig{})
	resolver := NewCachedPermissionsResolver(CachedPermissionsResolverConfig{
		Resolver: func(ctx context.Context) ([]string, error) {
			request, ok := CurrentPermissionsRequestFromContext(ctx)
			if !ok ||
				request.Principal.ApplicationSubject() != "user-1" ||
				request.Principal.TenantID() != "tenant-1" ||
				request.Version != "1" {
				t.Fatalf("current permission request=%+v ok=%t", request, ok)
			}
			return []string{"records.read"}, nil
		},
		Store: store,
		TTL:   time.Hour,
	})
	guard := newTestFreshnessGuard(
		t, now, activeAccountResolver(now),
		PermissionVersionResolverFunc(func(context.Context, AuthenticatedPrincipal) (PermissionVersionResult, error) {
			return PermissionVersionResult{Version: "1", Role: "office", ObservedAt: now}, nil
		}),
		resolver.ResolverFunc(),
	)
	result, err := guard.Authorize(context.Background(), AuthorizationFreshnessRequest{
		Operation: "records.read",
		Role:      "office",
		Principal: freshnessPrincipal(t, "aal1", "1", now),
	})
	if err != nil || result.Decision != FreshnessAllowed {
		t.Fatalf("normal read result=%+v err=%v", result, err)
	}
	deleted, more, err := resolver.InvalidateScope(context.Background(), PermissionInvalidationScope{
		ApplicationSubject: "user-1",
		TenantID:           "tenant-1",
		SessionID:          "local-session-1",
	}, 10)
	if err != nil || deleted != 1 || more {
		t.Fatalf("current scope invalidation deleted=%d more=%t err=%v", deleted, more, err)
	}
}
