package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testEmergencyPolicy(
	t *testing.T,
	now time.Time,
	revocations EmergencyAccessRevocationResolver,
	sink ActivitySink,
) *EmergencyAccessPolicy {
	t.Helper()
	if revocations == nil {
		revocations = EmergencyAccessRevocationResolverFunc(func(context.Context, string) (bool, error) {
			return false, nil
		})
	}
	if sink == nil {
		sink = ActivitySinkFunc(func(context.Context, ActivityEvent) error { return nil })
	}
	policy, err := NewEmergencyAccessPolicy(EmergencyAccessPolicyConfig{
		Owner: "security-owner@example.com", ApprovedAt: now,
		CredentialClass:   "isolated-break-glass",
		AllowedOperations: []string{"provider.account.activate", "provider.session.revoke"},
		ApprovedApprovers: []string{"approver-1@example.com", "approver-2@example.com", "approver-3@example.com"},
		RequiredApprovals: 2, MaxDuration: 30 * time.Minute,
		MonitoringDestination: "security-operations",
		ExerciseCadence:       30 * 24 * time.Hour,
		Revocations:           revocations,
		Revoker:               EmergencyAccessRevokerFunc(func(context.Context, string, string) error { return nil }),
		ActivitySink:          sink,
		Now:                   func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func validEmergencyGrant(now time.Time) EmergencyAccessGrant {
	return EmergencyAccessGrant{
		ID: "grant-1", ActorID: "operator@example.com",
		Approvers:         []string{"approver-1@example.com", "approver-2@example.com"},
		AllowedOperations: []string{"provider.account.activate"},
		CredentialClass:   "isolated-break-glass",
		Reason:            "restore access during identity outage",
		IssuedAt:          now.Add(-time.Minute), ExpiresAt: now.Add(15 * time.Minute),
	}
}

func TestEmergencyAccessPolicyAllowsAuditedIsolatedGrant(t *testing.T) {
	now := time.Now().UTC()
	var events []ActivityEvent
	policy := testEmergencyPolicy(t, now, nil, ActivitySinkFunc(func(_ context.Context, event ActivityEvent) error {
		events = append(events, event)
		return nil
	}))
	result, err := policy.Authorize(
		context.Background(), validEmergencyGrant(now),
		"provider.account.activate", "isolated-break-glass",
	)
	if err != nil || result.Decision != EmergencyAccessAllowed || len(events) != 1 {
		t.Fatalf("allow result=%+v events=%+v err=%v", result, events, err)
	}
}

func TestEmergencyAccessPolicyDenialMatrix(t *testing.T) {
	now := time.Now().UTC()
	outage := errors.New("revocation store unavailable")
	tests := []struct {
		name        string
		mutate      func(*EmergencyAccessGrant)
		operation   string
		credential  string
		revocations EmergencyAccessRevocationResolver
		reason      EmergencyAccessReason
		expected    error
	}{
		{
			name: "scope", mutate: func(*EmergencyAccessGrant) {},
			operation: "provider.session.revoke", credential: "isolated-break-glass",
			reason: EmergencyAccessReasonScope, expected: ErrEmergencyAccessDenied,
		},
		{
			name: "credential", mutate: func(*EmergencyAccessGrant) {},
			operation: "provider.account.activate", credential: "normal-session",
			reason: EmergencyAccessReasonCredential, expected: ErrEmergencyAccessDenied,
		},
		{
			name: "expired", mutate: func(grant *EmergencyAccessGrant) {
				grant.IssuedAt = now.Add(-20 * time.Minute)
				grant.ExpiresAt = now.Add(-time.Minute)
			},
			operation: "provider.account.activate", credential: "isolated-break-glass",
			reason: EmergencyAccessReasonExpired, expected: ErrEmergencyAccessDenied,
		},
		{
			name: "revoked", mutate: func(*EmergencyAccessGrant) {},
			operation: "provider.account.activate", credential: "isolated-break-glass",
			revocations: EmergencyAccessRevocationResolverFunc(func(context.Context, string) (bool, error) {
				return true, nil
			}),
			reason: EmergencyAccessReasonRevoked, expected: ErrEmergencyAccessDenied,
		},
		{
			name: "outage", mutate: func(*EmergencyAccessGrant) {},
			operation: "provider.account.activate", credential: "isolated-break-glass",
			revocations: EmergencyAccessRevocationResolverFunc(func(context.Context, string) (bool, error) {
				return false, outage
			}),
			reason: EmergencyAccessReasonDependencyOutage, expected: ErrEmergencyAccessUnavailable,
		},
		{
			name: "approvals", mutate: func(grant *EmergencyAccessGrant) {
				grant.Approvers = []string{"one@example.com"}
			},
			operation: "provider.account.activate", credential: "isolated-break-glass",
			reason: EmergencyAccessReasonInvalidGrant, expected: ErrEmergencyAccessDenied,
		},
		{
			name: "unknown approvers", mutate: func(grant *EmergencyAccessGrant) {
				grant.Approvers = []string{"unknown-1@example.com", "unknown-2@example.com"}
			},
			operation: "provider.account.activate", credential: "isolated-break-glass",
			reason: EmergencyAccessReasonInvalidGrant, expected: ErrEmergencyAccessDenied,
		},
		{
			name: "self approval whitespace", mutate: func(grant *EmergencyAccessGrant) {
				grant.ActorID = " operator@example.com "
				grant.Approvers = []string{"operator@example.com", "approver-2@example.com"}
			},
			operation: "provider.account.activate", credential: "isolated-break-glass",
			reason: EmergencyAccessReasonInvalidGrant, expected: ErrEmergencyAccessDenied,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			grant := validEmergencyGrant(now)
			tc.mutate(&grant)
			policy := testEmergencyPolicy(t, now, tc.revocations, nil)
			result, err := policy.Authorize(context.Background(), grant, tc.operation, tc.credential)
			if result.Decision != EmergencyAccessDenied || result.Reason != tc.reason || !errors.Is(err, tc.expected) {
				t.Fatalf("result=%+v err=%v; want reason=%q err=%v", result, err, tc.reason, tc.expected)
			}
		})
	}
}

func TestEmergencyAccessPolicyFailsClosedWhenAuditFails(t *testing.T) {
	now := time.Now().UTC()
	auditErr := errors.New("audit unavailable")
	policy := testEmergencyPolicy(t, now, nil, ActivitySinkFunc(func(context.Context, ActivityEvent) error {
		return auditErr
	}))
	result, err := policy.Authorize(
		context.Background(), validEmergencyGrant(now),
		"provider.account.activate", "isolated-break-glass",
	)
	if result.Decision != EmergencyAccessDenied ||
		result.Reason != EmergencyAccessReasonAuditFailure ||
		!errors.Is(err, auditErr) ||
		!errors.Is(err, ErrEmergencyAccessUnavailable) {
		t.Fatalf("audit failure result=%+v err=%v", result, err)
	}
}

func TestEmergencyAccessPolicyForcesAndAuditsRevocation(t *testing.T) {
	now := time.Now().UTC()
	var revokedGrant string
	var events []ActivityEvent
	policy, err := NewEmergencyAccessPolicy(EmergencyAccessPolicyConfig{
		Owner: "security-owner@example.com", ApprovedAt: now,
		CredentialClass:   "isolated-break-glass",
		AllowedOperations: []string{"provider.account.activate"},
		ApprovedApprovers: []string{"approver-1@example.com", "approver-2@example.com"},
		RequiredApprovals: 2, MaxDuration: 30 * time.Minute,
		MonitoringDestination: "security-operations",
		ExerciseCadence:       30 * 24 * time.Hour,
		Revocations:           EmergencyAccessRevocationResolverFunc(func(context.Context, string) (bool, error) { return false, nil }),
		Revoker: EmergencyAccessRevokerFunc(func(_ context.Context, grantID, _ string) error {
			revokedGrant = grantID
			return nil
		}),
		ActivitySink: ActivitySinkFunc(func(_ context.Context, event ActivityEvent) error {
			events = append(events, event)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Revoke(context.Background(), "grant-1", "security-owner@example.com", "incident closed"); err != nil {
		t.Fatal(err)
	}
	if revokedGrant != "grant-1" || len(events) != 1 ||
		events[0].Metadata["reason"] != EmergencyAccessReasonRevoked {
		t.Fatalf("forced revocation grant=%q events=%+v", revokedGrant, events)
	}
}

func TestEmergencyAccessPolicyAuditsFailedForcedRevocation(t *testing.T) {
	now := time.Now().UTC()
	revokeErr := errors.New("revocation store unavailable")
	var events []ActivityEvent
	policy, err := NewEmergencyAccessPolicy(EmergencyAccessPolicyConfig{
		Owner: "security-owner@example.com", ApprovedAt: now,
		CredentialClass:   "isolated-break-glass",
		AllowedOperations: []string{"provider.account.activate"},
		ApprovedApprovers: []string{"approver-1@example.com", "approver-2@example.com"},
		RequiredApprovals: 2, MaxDuration: 30 * time.Minute,
		MonitoringDestination: "security-operations",
		ExerciseCadence:       30 * 24 * time.Hour,
		Revocations:           EmergencyAccessRevocationResolverFunc(func(context.Context, string) (bool, error) { return false, nil }),
		Revoker: EmergencyAccessRevokerFunc(func(context.Context, string, string) error {
			return revokeErr
		}),
		ActivitySink: ActivitySinkFunc(func(_ context.Context, event ActivityEvent) error {
			events = append(events, event)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = policy.Revoke(context.Background(), "grant-1", "security-owner@example.com", "incident closed")
	if !errors.Is(err, ErrEmergencyAccessUnavailable) || !errors.Is(err, revokeErr) ||
		len(events) != 1 ||
		events[0].Metadata["reason"] != EmergencyAccessReasonDependencyOutage {
		t.Fatalf("failed revocation events=%+v err=%v", events, err)
	}
}

func TestEmergencyAccessPolicyRejectsMissingIsolationOrMonitoring(t *testing.T) {
	now := time.Now().UTC()
	_, err := NewEmergencyAccessPolicy(EmergencyAccessPolicyConfig{
		Owner: "owner", ApprovedAt: now, CredentialClass: "",
		AllowedOperations: []string{"provider.account.activate"},
		ApprovedApprovers: []string{"approver-1", "approver-2"},
		RequiredApprovals: 2, MaxDuration: 30 * time.Minute,
		MonitoringDestination: "", ExerciseCadence: 30 * 24 * time.Hour,
		Revocations:  EmergencyAccessRevocationResolverFunc(func(context.Context, string) (bool, error) { return false, nil }),
		Revoker:      EmergencyAccessRevokerFunc(func(context.Context, string, string) error { return nil }),
		ActivitySink: ActivitySinkFunc(func(context.Context, ActivityEvent) error { return nil }),
	})
	if !errors.Is(err, ErrFreshnessPolicyInvalid) {
		t.Fatalf("invalid emergency policy error=%v", err)
	}
}
