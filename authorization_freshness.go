package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

type FreshnessDecision string

const (
	FreshnessAllowed FreshnessDecision = "allowed"
	FreshnessDenied  FreshnessDecision = "denied"
	FreshnessStepUp  FreshnessDecision = "step_up_required"
)

type FreshnessReason string

const (
	FreshnessReasonSatisfied         FreshnessReason = "satisfied"
	FreshnessReasonUnknownOperation  FreshnessReason = "unknown_operation"
	FreshnessReasonSessionInvalid    FreshnessReason = "session_invalid"
	FreshnessReasonAssurance         FreshnessReason = "assurance"
	FreshnessReasonAccountState      FreshnessReason = "account_state"
	FreshnessReasonPermissionVersion FreshnessReason = "permission_version"
	FreshnessReasonPermissionDenied  FreshnessReason = "permission_denied"
	FreshnessReasonDependencyOutage  FreshnessReason = "dependency_outage"
)

type AuthorizationFreshnessRequest struct {
	Operation string
	// Role is retained for source compatibility but is not authorization
	// evidence. The guard selects policy from PermissionVersionResult.Role.
	// Deprecated: populate the authoritative role in PermissionVersionResult.
	Role      string
	Principal AuthenticatedPrincipal
}

type AuthorizationFreshnessResult struct {
	Decision             FreshnessDecision
	Reason               FreshnessReason
	Operation            string
	Policy               FreshnessOperationPolicy
	Assurance            AssuranceResult
	AccountState         AccountStateResolution
	SessionVersion       string
	CurrentVersion       string
	CurrentRole          string
	Permissions          []string
	PermissionsRefreshed bool
}

type AuthorizationFreshnessGuardConfig struct {
	Policy             *FreshnessPolicy
	AccountStates      AccountStateResolver
	PermissionVersions PermissionVersionResolver
	Permissions        PermissionResolverFunc
	Assurance          AssuranceGuard
	ActivitySink       ActivitySink
	Now                func() time.Time
}

// AuthorizationFreshnessGuard composes current session, assurance, account
// state, permission version, and current permission checks.
type AuthorizationFreshnessGuard struct {
	policy             *FreshnessPolicy
	accountStates      AccountStateResolver
	permissionVersions PermissionVersionResolver
	permissions        PermissionResolverFunc
	assurance          AssuranceGuard
	activitySink       ActivitySink
	now                func() time.Time
}

func NewAuthorizationFreshnessGuard(cfg AuthorizationFreshnessGuardConfig) (*AuthorizationFreshnessGuard, error) {
	if cfg.Policy == nil || cfg.AccountStates == nil || cfg.PermissionVersions == nil || cfg.Permissions == nil {
		return nil, fmt.Errorf("%w: policy and all freshness resolvers are required", ErrFreshnessPolicyInvalid)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	if cfg.Assurance.Now == nil {
		cfg.Assurance.Now = now
	}
	if cfg.Assurance.ActivitySink == nil {
		cfg.Assurance.ActivitySink = cfg.ActivitySink
	}
	return &AuthorizationFreshnessGuard{
		policy: cfg.Policy, accountStates: cfg.AccountStates,
		permissionVersions: cfg.PermissionVersions, permissions: cfg.Permissions,
		assurance: cfg.Assurance, activitySink: cfg.ActivitySink, now: now,
	}, nil
}

//nolint:gocyclo,funlen // The fail-closed authorization gates remain sequential and explicit for auditability.
func (g *AuthorizationFreshnessGuard) Authorize(
	ctx context.Context,
	request AuthorizationFreshnessRequest,
) (AuthorizationFreshnessResult, error) {
	result := AuthorizationFreshnessResult{
		Decision:  FreshnessDenied,
		Reason:    FreshnessReasonUnknownOperation,
		Operation: strings.TrimSpace(request.Operation),
	}
	if g == nil || g.policy == nil {
		return result, ErrFreshnessPolicyInvalid
	}
	// Reject unknown operations without consulting external authorization
	// state. The role-specific policy is selected only after the current
	// host-owned role is resolved.
	if _, err := g.policy.Operation(result.Operation, ""); err != nil {
		g.emit(ctx, result, err)
		return result, err
	}

	principal, session, err := g.resolvePrincipalAndSession(ctx, request.Principal)
	if err != nil {
		result.Reason = FreshnessReasonSessionInvalid
		g.emit(ctx, result, err)
		return result, err
	}
	result.SessionVersion = strings.TrimSpace(principal.PermissionVersion())

	current, err := g.permissionVersions.ResolvePermissionVersion(ctx, principal)
	if err != nil || strings.TrimSpace(current.Version) == "" {
		result.Reason = FreshnessReasonDependencyOutage
		if err == nil {
			err = ErrPermissionVersionMissing
		}
		g.emit(ctx, result, err)
		return result, err
	}
	result.CurrentVersion = strings.TrimSpace(current.Version)
	result.CurrentRole = strings.ToLower(strings.TrimSpace(current.Role))
	if result.CurrentRole == "" {
		result.Reason = FreshnessReasonDependencyOutage
		g.emit(ctx, result, ErrAuthorizationRoleMissing)
		return result, ErrAuthorizationRoleMissing
	}

	policy, err := g.policy.Operation(result.Operation, result.CurrentRole)
	if err != nil {
		g.emit(ctx, result, err)
		return result, err
	}
	result.Policy = policy
	if policy.RequireProviderSession && session == nil {
		result.Reason = FreshnessReasonSessionInvalid
		g.emit(ctx, result, ErrProviderSessionUnavailable)
		return result, ErrProviderSessionUnavailable
	}

	assuranceCtx := ctx
	if _, assuranceErr := AssuranceFromContext(ctx); assuranceErr != nil {
		level, parseErr := ParseAssuranceLevel(principal.AssuranceLevel())
		if parseErr == nil {
			assuranceCtx = WithAssuranceContext(ctx, AssuranceContext{
				Level: level, Methods: principal.AssuranceMethods(),
				AuthenticationAt: principal.AuthenticationAt(),
			})
		}
	}
	assurance, err := g.assurance.Require(assuranceCtx, AssuranceRequirement{
		Level: policy.RequiredAssurance, MaxAuthenticationAge: policy.MaxAuthenticationAge,
		Operation: policy.Operation, AllowStepUp: policy.AllowStepUp,
	})
	result.Assurance = assurance
	if err != nil {
		result.Reason = FreshnessReasonAssurance
		if assurance.Decision == AssuranceStepUpRequired {
			result.Decision = FreshnessStepUp
		}
		g.emit(ctx, result, err)
		return result, err
	}

	accountState, err := g.accountStates.ResolveCurrentAccountState(ctx, AccountStateRequest{
		Principal: principal, MaximumStaleness: policy.MaxAccountStateAge,
		Privileged: policy.Risk == OperationRiskPrivileged,
	})
	result.AccountState = accountState
	if err != nil || accountState.State != AccountStateActive {
		result.Reason = FreshnessReasonAccountState
		if err == nil {
			err = ErrAccountStateUnknown
		}
		g.emit(ctx, result, err)
		return result, err
	}

	mismatch := result.SessionVersion == "" || result.SessionVersion != result.CurrentVersion
	if mismatch && !policy.RefreshOnPermissionMismatch {
		result.Reason = FreshnessReasonPermissionVersion
		g.emit(ctx, result, ErrPermissionVersionMismatch)
		return result, ErrPermissionVersionMismatch
	}

	sessionID := ""
	if session != nil {
		sessionID = session.ID
	}
	permissions, err := g.permissions.ResolveCurrentPermissions(ctx, CurrentPermissionsRequest{
		Principal:    principal,
		Version:      result.CurrentVersion,
		Role:         result.CurrentRole,
		SessionID:    sessionID,
		ForceRefresh: mismatch,
	})
	if err != nil {
		result.Reason = FreshnessReasonDependencyOutage
		g.emit(ctx, result, err)
		return result, err
	}
	result.Permissions = slices.Clone(permissions)
	result.PermissionsRefreshed = mismatch
	if !slices.Contains(permissions, policy.RequiredPermission) {
		result.Reason = FreshnessReasonPermissionDenied
		g.emit(ctx, result, ErrAuthorizationFreshnessDenied)
		return result, ErrAuthorizationFreshnessDenied
	}

	if policy.RequireProviderSession && session == nil {
		result.Reason = FreshnessReasonSessionInvalid
		g.emit(ctx, result, ErrProviderSessionUnavailable)
		return result, ErrProviderSessionUnavailable
	}
	result.Decision = FreshnessAllowed
	result.Reason = FreshnessReasonSatisfied
	g.emit(ctx, result, nil)
	return result, nil
}

func (g *AuthorizationFreshnessGuard) resolvePrincipalAndSession(
	ctx context.Context,
	explicit AuthenticatedPrincipal,
) (AuthenticatedPrincipal, *ProviderSession, error) {
	var principal AuthenticatedPrincipal
	var session *ProviderSession
	if providerContext, ok := ProviderSessionFromContext(ctx); ok {
		principal = providerContext.Principal
		sessionCopy := providerContext.Session
		session = &sessionCopy
	} else {
		principal = explicit.Clone()
	}
	if strings.TrimSpace(principal.ApplicationSubject()) == "" {
		return AuthenticatedPrincipal{}, nil, ErrProviderSessionUnavailable
	}
	now := g.now()
	if !principal.ExpiresAt().IsZero() && !now.Before(principal.ExpiresAt()) {
		return AuthenticatedPrincipal{}, nil, ErrProviderSessionRevoked
	}
	if session != nil && (!session.Status.Usable() ||
		(!session.IdleExpiresAt.IsZero() && !now.Before(session.IdleExpiresAt)) ||
		(!session.MaxExpiresAt.IsZero() && !now.Before(session.MaxExpiresAt)) ||
		(!principal.ExpiresAt().IsZero() && !now.Before(principal.ExpiresAt()))) {
		return AuthenticatedPrincipal{}, nil, ErrProviderSessionRevoked
	}
	return principal, session, nil
}

func (g *AuthorizationFreshnessGuard) emit(
	ctx context.Context,
	result AuthorizationFreshnessResult,
	err error,
) {
	if g == nil || g.activitySink == nil {
		return
	}
	metadata := map[string]any{
		"decision":  result.Decision,
		"reason":    result.Reason,
		"operation": result.Operation,
		"risk":      result.Policy.Risk,
	}
	if err != nil {
		metadata["error"] = "authorization freshness check failed"
	}
	_ = g.activitySink.Record(ctx, ActivityEvent{
		EventType: ActivityEventAuthorizationFreshness,
		Metadata:  metadata,
	})
}
