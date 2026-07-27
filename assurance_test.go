package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestParseAssuranceLevelAndOrdering(t *testing.T) {
	for input, expected := range map[string]AssuranceLevel{
		"aal1": AssuranceAAL1,
		"AAL2": AssuranceAAL2,
	} {
		got, err := ParseAssuranceLevel(input)
		if err != nil || got != expected {
			t.Fatalf("ParseAssuranceLevel(%q) = %q, %v; want %q", input, got, err, expected)
		}
	}
	if _, err := ParseAssuranceLevel(""); !errors.Is(err, ErrAssuranceMissing) {
		t.Fatalf("missing assurance error = %v", err)
	}
	if _, err := ParseAssuranceLevel("aal3"); !errors.Is(err, ErrAssuranceUnknown) {
		t.Fatalf("unknown assurance error = %v", err)
	}
	if !AssuranceAAL2.Meets(AssuranceAAL1) || AssuranceAAL1.Meets(AssuranceAAL2) {
		t.Fatal("assurance ordering is incorrect")
	}
}

func TestAssuranceContextIsIsolated(t *testing.T) {
	input := AssuranceContext{
		Level:            AssuranceAAL2,
		Methods:          []string{"totp"},
		AuthenticationAt: time.Now(),
	}
	ctx := WithAssuranceContext(context.Background(), input)
	input.Methods[0] = "mutated"

	got, err := AssuranceFromContext(ctx)
	if err != nil || got.Methods[0] != "totp" {
		t.Fatalf("isolated context = %+v, %v", got, err)
	}
	got.Methods[0] = "changed"
	again, _ := AssuranceFromContext(ctx)
	if again.Methods[0] != "totp" {
		t.Fatalf("context result leaked mutation: %+v", again)
	}
}

func TestAssuranceFromProviderPrincipal(t *testing.T) {
	now := time.Now().UTC()
	principal, err := NewAuthenticatedPrincipal(AuthenticatedPrincipalInput{
		ApplicationSubject: "user-1",
		Provider:           "supabase",
		ProviderSubject:    "provider-user-1",
		AssuranceLevel:     "aal2",
		AssuranceMethods:   []string{"password", "totp"},
		AuthenticationAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithProviderSessionContext(context.Background(), ProviderSession{}, principal)

	got, err := AssuranceFromContext(ctx)
	if err != nil || got.Level != AssuranceAAL2 || len(got.Methods) != 2 || !got.AuthenticationAt.Equal(now) {
		t.Fatalf("principal assurance = %+v, %v", got, err)
	}
}

func TestAssuranceGuardOutcomes(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name        string
		ctx         context.Context
		requirement AssuranceRequirement
		decision    AssuranceDecision
		err         error
	}{
		{
			name: "sufficient",
			ctx: WithAssuranceContext(context.Background(), AssuranceContext{
				Level: AssuranceAAL2, AuthenticationAt: now.Add(-time.Minute),
			}),
			requirement: AssuranceRequirement{Level: AssuranceAAL1, MaxAuthenticationAge: time.Hour},
			decision:    AssuranceAllowed,
		},
		{
			name:        "missing",
			ctx:         context.Background(),
			requirement: AssuranceRequirement{Level: AssuranceAAL1},
			decision:    AssuranceDenied,
			err:         ErrAssuranceMissing,
		},
		{
			name: "insufficient step up",
			ctx: WithAssuranceContext(context.Background(), AssuranceContext{
				Level: AssuranceAAL1, AuthenticationAt: now,
			}),
			requirement: AssuranceRequirement{Level: AssuranceAAL2, AllowStepUp: true},
			decision:    AssuranceStepUpRequired,
			err:         ErrAssuranceStepUpRequired,
		},
		{
			name: "stale",
			ctx: WithAssuranceContext(context.Background(), AssuranceContext{
				Level: AssuranceAAL2, AuthenticationAt: now.Add(-2 * time.Hour),
			}),
			requirement: AssuranceRequirement{Level: AssuranceAAL2, MaxAuthenticationAge: time.Hour},
			decision:    AssuranceDenied,
			err:         ErrAssuranceStale,
		},
		{
			name: "future time",
			ctx: WithAssuranceContext(context.Background(), AssuranceContext{
				Level: AssuranceAAL2, AuthenticationAt: now.Add(time.Minute),
			}),
			requirement: AssuranceRequirement{Level: AssuranceAAL2, MaxAuthenticationAge: time.Hour},
			decision:    AssuranceDenied,
			err:         ErrAssuranceStale,
		},
		{
			name: "unknown",
			ctx: WithAssuranceContext(context.Background(), AssuranceContext{
				Level: AssuranceUnknown, AuthenticationAt: now,
			}),
			requirement: AssuranceRequirement{Level: AssuranceAAL1, AllowStepUp: true},
			decision:    AssuranceDenied,
			err:         ErrAssuranceUnknown,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := (AssuranceGuard{Now: func() time.Time { return now }}).Require(tc.ctx, tc.requirement)
			if result.Decision != tc.decision || !errors.Is(err, tc.err) {
				t.Fatalf("result=%+v err=%v; want decision=%q err=%v", result, err, tc.decision, tc.err)
			}
		})
	}
}

func TestAssuranceGuardEmitsSafeStableAuditReason(t *testing.T) {
	var events []ActivityEvent
	guard := AssuranceGuard{
		ActivitySink: ActivitySinkFunc(func(_ context.Context, event ActivityEvent) error {
			events = append(events, event)
			return nil
		}),
	}
	result, err := guard.Require(context.Background(), AssuranceRequirement{
		Level: AssuranceAAL2, Operation: "provider.account.suspend", AllowStepUp: true,
	})
	if !errors.Is(err, ErrAssuranceStepUpRequired) || result.Reason != AssuranceReasonMissing {
		t.Fatalf("unexpected result=%+v err=%v", result, err)
	}
	if len(events) != 1 || events[0].EventType != ActivityEventAssuranceStepUp ||
		events[0].Metadata["reason"] != AssuranceReasonMissing {
		t.Fatalf("unexpected audit events: %+v", events)
	}
}
