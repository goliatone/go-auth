package auth

import (
	"fmt"
	"strings"
	"time"
)

const (
	MaxNormalAccountStateCache    = 15 * time.Minute
	MaxPrivilegedStateCache       = time.Minute
	MaxAssuranceAuthenticationAge = 24 * time.Hour
	MaxAuthorizationPropagation   = time.Hour
)

type OperationRisk string

const (
	OperationRiskNormalRead OperationRisk = "normal_read"
	OperationRiskPrivileged OperationRisk = "privileged"
)

type FreshnessOperationPolicy struct {
	Operation                   string
	Risk                        OperationRisk
	RequiredPermission          string
	RequiredAssurance           AssuranceLevel
	MaxAuthenticationAge        time.Duration
	MaxAccountStateAge          time.Duration
	AllowStepUp                 bool
	RefreshOnPermissionMismatch bool
	RequireProviderSession      bool
}

type RoleFreshnessPolicy struct {
	Role   string
	Policy FreshnessOperationPolicy
}

type FreshnessPolicyConfig struct {
	Owner             string
	ApprovedAt        time.Time
	PropagationTarget time.Duration
	Operations        []FreshnessOperationPolicy
	RoleOverrides     []RoleFreshnessPolicy
}

// FreshnessPolicy is immutable after construction.
type FreshnessPolicy struct {
	owner             string
	approvedAt        time.Time
	propagationTarget time.Duration
	operations        map[string]FreshnessOperationPolicy
	roleOverrides     map[string]FreshnessOperationPolicy
}

func NewFreshnessPolicy(cfg FreshnessPolicyConfig) (*FreshnessPolicy, error) {
	if strings.TrimSpace(cfg.Owner) == "" || cfg.ApprovedAt.IsZero() ||
		cfg.PropagationTarget <= 0 || cfg.PropagationTarget > MaxAuthorizationPropagation ||
		len(cfg.Operations) == 0 {
		return nil, fmt.Errorf("%w: owner approval, secure propagation target, and operations are required", ErrFreshnessPolicyInvalid)
	}
	policy := &FreshnessPolicy{
		owner:             strings.TrimSpace(cfg.Owner),
		approvedAt:        cfg.ApprovedAt,
		propagationTarget: cfg.PropagationTarget,
		operations:        map[string]FreshnessOperationPolicy{},
		roleOverrides:     map[string]FreshnessOperationPolicy{},
	}
	for _, operation := range cfg.Operations {
		normalized, err := validateFreshnessOperationPolicy(operation)
		if err != nil {
			return nil, err
		}
		if _, exists := policy.operations[normalized.Operation]; exists {
			return nil, fmt.Errorf("%w: duplicate operation %q", ErrFreshnessPolicyInvalid, normalized.Operation)
		}
		policy.operations[normalized.Operation] = normalized
	}
	for _, override := range cfg.RoleOverrides {
		role := strings.ToLower(strings.TrimSpace(override.Role))
		if role == "" {
			return nil, fmt.Errorf("%w: role override requires a role", ErrFreshnessPolicyInvalid)
		}
		normalized, err := validateFreshnessOperationPolicy(override.Policy)
		if err != nil {
			return nil, err
		}
		if _, exists := policy.operations[normalized.Operation]; !exists {
			return nil, fmt.Errorf("%w: role override references unknown operation %q", ErrFreshnessPolicyInvalid, normalized.Operation)
		}
		key := freshnessRoleKey(role, normalized.Operation)
		if _, exists := policy.roleOverrides[key]; exists {
			return nil, fmt.Errorf("%w: duplicate role operation %q", ErrFreshnessPolicyInvalid, key)
		}
		policy.roleOverrides[key] = normalized
	}
	return policy, nil
}

func (p *FreshnessPolicy) Operation(operation, role string) (FreshnessOperationPolicy, error) {
	if p == nil {
		return FreshnessOperationPolicy{}, ErrFreshnessPolicyInvalid
	}
	operation = strings.TrimSpace(operation)
	role = strings.ToLower(strings.TrimSpace(role))
	if role != "" {
		if override, ok := p.roleOverrides[freshnessRoleKey(role, operation)]; ok {
			return override, nil
		}
	}
	policy, ok := p.operations[operation]
	if !ok {
		return FreshnessOperationPolicy{}, fmt.Errorf("%w: unknown operation %q", ErrFreshnessPolicyInvalid, operation)
	}
	return policy, nil
}

func (p *FreshnessPolicy) Owner() string {
	if p == nil {
		return ""
	}
	return p.owner
}

func (p *FreshnessPolicy) ApprovedAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.approvedAt
}

func (p *FreshnessPolicy) PropagationTarget() time.Duration {
	if p == nil {
		return 0
	}
	return p.propagationTarget
}

func validateFreshnessOperationPolicy(policy FreshnessOperationPolicy) (FreshnessOperationPolicy, error) {
	policy.Operation = strings.TrimSpace(policy.Operation)
	policy.RequiredPermission = strings.TrimSpace(policy.RequiredPermission)
	if policy.Operation == "" || policy.RequiredPermission == "" ||
		!policy.RequiredAssurance.validRequirement() ||
		policy.MaxAuthenticationAge <= 0 ||
		policy.MaxAuthenticationAge > MaxAssuranceAuthenticationAge ||
		policy.MaxAccountStateAge <= 0 {
		return FreshnessOperationPolicy{}, fmt.Errorf("%w: operation %q has incomplete or insecure bounds", ErrFreshnessPolicyInvalid, policy.Operation)
	}
	switch policy.Risk {
	case OperationRiskNormalRead:
		if policy.MaxAccountStateAge > MaxNormalAccountStateCache {
			return FreshnessOperationPolicy{}, fmt.Errorf("%w: normal-read account-state cache exceeds bound", ErrFreshnessPolicyInvalid)
		}
	case OperationRiskPrivileged:
		if policy.MaxAccountStateAge > MaxPrivilegedStateCache ||
			!policy.RequireProviderSession {
			return FreshnessOperationPolicy{}, fmt.Errorf("%w: privileged operation must require a current provider session and bounded state", ErrFreshnessPolicyInvalid)
		}
	default:
		return FreshnessOperationPolicy{}, fmt.Errorf("%w: operation %q has unknown risk", ErrFreshnessPolicyInvalid, policy.Operation)
	}
	return policy, nil
}

func freshnessRoleKey(role, operation string) string {
	return strings.ToLower(strings.TrimSpace(role)) + "\x00" + strings.TrimSpace(operation)
}
