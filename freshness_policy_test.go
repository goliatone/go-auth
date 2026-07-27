package auth

import (
	"errors"
	"testing"
	"time"
)

func validFreshnessPolicyConfig(now time.Time) FreshnessPolicyConfig {
	return FreshnessPolicyConfig{
		Owner:             "security-owner@example.com",
		ApprovedAt:        now,
		PropagationTarget: 5 * time.Minute,
		Operations: []FreshnessOperationPolicy{
			{
				Operation:                   "records.read",
				Risk:                        OperationRiskNormalRead,
				RequiredPermission:          "records.read",
				RequiredAssurance:           AssuranceAAL1,
				MaxAuthenticationAge:        12 * time.Hour,
				MaxAccountStateAge:          5 * time.Minute,
				RefreshOnPermissionMismatch: true,
			},
			{
				Operation:                   "provider.account.suspend",
				Risk:                        OperationRiskPrivileged,
				RequiredPermission:          "provider.account.suspend",
				RequiredAssurance:           AssuranceAAL2,
				MaxAuthenticationAge:        15 * time.Minute,
				MaxAccountStateAge:          30 * time.Second,
				AllowStepUp:                 true,
				RefreshOnPermissionMismatch: true,
				RequireProviderSession:      true,
			},
		},
		RoleOverrides: []RoleFreshnessPolicy{{
			Role: "field",
			Policy: FreshnessOperationPolicy{
				Operation:                   "records.read",
				Risk:                        OperationRiskNormalRead,
				RequiredPermission:          "records.read",
				RequiredAssurance:           AssuranceAAL2,
				MaxAuthenticationAge:        time.Hour,
				MaxAccountStateAge:          time.Minute,
				RefreshOnPermissionMismatch: true,
			},
		}},
	}
}

func TestFreshnessPolicyOperationAndRoleMatrix(t *testing.T) {
	now := time.Now().UTC()
	policy, err := NewFreshnessPolicy(validFreshnessPolicyConfig(now))
	if err != nil {
		t.Fatal(err)
	}
	normal, err := policy.Operation("records.read", "office")
	if err != nil || normal.RequiredAssurance != AssuranceAAL1 {
		t.Fatalf("normal policy=%+v err=%v", normal, err)
	}
	field, err := policy.Operation("records.read", "field")
	if err != nil || field.RequiredAssurance != AssuranceAAL2 {
		t.Fatalf("field override=%+v err=%v", field, err)
	}
	if policy.Owner() != "security-owner@example.com" || policy.PropagationTarget() != 5*time.Minute {
		t.Fatalf("policy approval metadata mismatch")
	}
	if _, err := policy.Operation("unknown", "admin"); !errors.Is(err, ErrFreshnessPolicyInvalid) {
		t.Fatalf("unknown operation error=%v", err)
	}
}

func TestFreshnessPolicyRejectsMissingApprovalAndInsecureBounds(t *testing.T) {
	now := time.Now().UTC()
	tests := map[string]func(*FreshnessPolicyConfig){
		"owner":                      func(cfg *FreshnessPolicyConfig) { cfg.Owner = "" },
		"approval":                   func(cfg *FreshnessPolicyConfig) { cfg.ApprovedAt = time.Time{} },
		"propagation":                func(cfg *FreshnessPolicyConfig) { cfg.PropagationTarget = 2 * time.Hour },
		"unknown risk":               func(cfg *FreshnessPolicyConfig) { cfg.Operations[0].Risk = "mystery" },
		"normal cache":               func(cfg *FreshnessPolicyConfig) { cfg.Operations[0].MaxAccountStateAge = time.Hour },
		"privileged session":         func(cfg *FreshnessPolicyConfig) { cfg.Operations[1].RequireProviderSession = false },
		"authentication age":         func(cfg *FreshnessPolicyConfig) { cfg.Operations[0].MaxAuthenticationAge = 48 * time.Hour },
		"unknown operation override": func(cfg *FreshnessPolicyConfig) { cfg.RoleOverrides[0].Policy.Operation = "missing" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validFreshnessPolicyConfig(now)
			mutate(&cfg)
			if _, err := NewFreshnessPolicy(cfg); !errors.Is(err, ErrFreshnessPolicyInvalid) {
				t.Fatalf("expected invalid policy, got %v", err)
			}
		})
	}
}
