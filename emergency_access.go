package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const MaxEmergencyAccessDuration = time.Hour

type EmergencyAccessRevocationResolver interface {
	EmergencyAccessRevoked(context.Context, string) (bool, error)
}

type EmergencyAccessRevocationResolverFunc func(context.Context, string) (bool, error)

func (f EmergencyAccessRevocationResolverFunc) EmergencyAccessRevoked(ctx context.Context, grantID string) (bool, error) {
	if f == nil {
		return false, ErrEmergencyAccessUnavailable
	}
	return f(ctx, grantID)
}

type EmergencyAccessRevoker interface {
	RevokeEmergencyAccess(context.Context, string, string) error
}

type EmergencyAccessRevokerFunc func(context.Context, string, string) error

func (f EmergencyAccessRevokerFunc) RevokeEmergencyAccess(ctx context.Context, grantID, reason string) error {
	if f == nil {
		return ErrEmergencyAccessUnavailable
	}
	return f(ctx, grantID, reason)
}

type EmergencyAccessPolicyConfig struct {
	Owner                 string
	ApprovedAt            time.Time
	CredentialClass       string
	AllowedOperations     []string
	ApprovedApprovers     []string
	RequiredApprovals     int
	MaxDuration           time.Duration
	MonitoringDestination string
	ExerciseCadence       time.Duration
	Revocations           EmergencyAccessRevocationResolver
	Revoker               EmergencyAccessRevoker
	ActivitySink          ActivitySink
	Now                   func() time.Time
}

type EmergencyAccessPolicy struct {
	owner                 string
	approvedAt            time.Time
	credentialClass       string
	allowedOperations     map[string]struct{}
	approvedApprovers     map[string]struct{}
	requiredApprovals     int
	maxDuration           time.Duration
	monitoringDestination string
	exerciseCadence       time.Duration
	revocations           EmergencyAccessRevocationResolver
	revoker               EmergencyAccessRevoker
	activitySink          ActivitySink
	now                   func() time.Time
}

type EmergencyAccessGrant struct {
	ID                string
	ActorID           string
	Approvers         []string
	AllowedOperations []string
	CredentialClass   string
	Reason            string
	IssuedAt          time.Time
	ExpiresAt         time.Time
}

type EmergencyAccessDecision string

const (
	EmergencyAccessAllowed EmergencyAccessDecision = "allowed"
	EmergencyAccessDenied  EmergencyAccessDecision = "denied"
)

type EmergencyAccessReason string

const (
	EmergencyAccessReasonAllowed          EmergencyAccessReason = "allowed"
	EmergencyAccessReasonInvalidGrant     EmergencyAccessReason = "invalid_grant"
	EmergencyAccessReasonCredential       EmergencyAccessReason = "credential_isolation" // #nosec G101 -- Audit reason code, not a credential.
	EmergencyAccessReasonScope            EmergencyAccessReason = "scope_violation"
	EmergencyAccessReasonExpired          EmergencyAccessReason = "expired"
	EmergencyAccessReasonRevoked          EmergencyAccessReason = "revoked"
	EmergencyAccessReasonDependencyOutage EmergencyAccessReason = "dependency_outage"
	EmergencyAccessReasonAuditFailure     EmergencyAccessReason = "audit_failure"
)

type EmergencyAccessResult struct {
	Decision  EmergencyAccessDecision
	Reason    EmergencyAccessReason
	GrantID   string
	ActorID   string
	Operation string
	ExpiresAt time.Time
}

//nolint:gocyclo // Every emergency-policy invariant is validated explicitly at construction.
func NewEmergencyAccessPolicy(cfg EmergencyAccessPolicyConfig) (*EmergencyAccessPolicy, error) {
	cfg.Owner = strings.TrimSpace(cfg.Owner)
	cfg.CredentialClass = strings.TrimSpace(cfg.CredentialClass)
	cfg.MonitoringDestination = strings.TrimSpace(cfg.MonitoringDestination)
	if cfg.Owner == "" || cfg.ApprovedAt.IsZero() || cfg.CredentialClass == "" ||
		cfg.RequiredApprovals < 2 || cfg.RequiredApprovals > 5 ||
		cfg.MaxDuration <= 0 || cfg.MaxDuration > MaxEmergencyAccessDuration ||
		cfg.MonitoringDestination == "" ||
		cfg.ExerciseCadence <= 0 || cfg.ExerciseCadence > 90*24*time.Hour ||
		cfg.Revocations == nil || cfg.Revoker == nil || cfg.ActivitySink == nil {
		return nil, fmt.Errorf("%w: emergency policy requires approval, isolation, monitoring, revocation, and audit", ErrFreshnessPolicyInvalid)
	}
	operations := map[string]struct{}{}
	for _, operation := range cfg.AllowedOperations {
		operation = strings.TrimSpace(operation)
		if operation == "" {
			return nil, ErrFreshnessPolicyInvalid
		}
		if _, duplicate := operations[operation]; duplicate {
			return nil, ErrFreshnessPolicyInvalid
		}
		operations[operation] = struct{}{}
	}
	if len(operations) == 0 {
		return nil, ErrFreshnessPolicyInvalid
	}
	approvers := map[string]struct{}{}
	for _, approver := range cfg.ApprovedApprovers {
		approver = strings.TrimSpace(approver)
		if approver == "" {
			return nil, ErrFreshnessPolicyInvalid
		}
		if _, duplicate := approvers[approver]; duplicate {
			return nil, ErrFreshnessPolicyInvalid
		}
		approvers[approver] = struct{}{}
	}
	if len(approvers) < cfg.RequiredApprovals {
		return nil, fmt.Errorf("%w: emergency policy requires enough named approvers for its quorum", ErrFreshnessPolicyInvalid)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &EmergencyAccessPolicy{
		owner: cfg.Owner, approvedAt: cfg.ApprovedAt,
		credentialClass: cfg.CredentialClass, allowedOperations: operations,
		approvedApprovers: approvers,
		requiredApprovals: cfg.RequiredApprovals, maxDuration: cfg.MaxDuration,
		monitoringDestination: cfg.MonitoringDestination,
		exerciseCadence:       cfg.ExerciseCadence, revocations: cfg.Revocations, revoker: cfg.Revoker,
		activitySink: cfg.ActivitySink, now: cfg.Now,
	}, nil
}

func (p *EmergencyAccessPolicy) Revoke(
	ctx context.Context,
	grantID, actorID, reason string,
) error {
	grantID = strings.TrimSpace(grantID)
	actorID = strings.TrimSpace(actorID)
	reason = strings.TrimSpace(reason)
	if p == nil || grantID == "" || actorID == "" || reason == "" {
		return ErrEmergencyAccessDenied
	}
	if err := p.revoker.RevokeEmergencyAccess(ctx, grantID, reason); err != nil {
		auditErr := p.audit(ctx, EmergencyAccessResult{
			Decision:  EmergencyAccessDenied,
			Reason:    EmergencyAccessReasonDependencyOutage,
			GrantID:   grantID,
			ActorID:   actorID,
			Operation: "emergency_access.revoke",
		})
		return errors.Join(ErrEmergencyAccessUnavailable, err, auditErr)
	}
	auditErr := p.audit(ctx, EmergencyAccessResult{
		Decision:  EmergencyAccessDenied,
		Reason:    EmergencyAccessReasonRevoked,
		GrantID:   grantID,
		ActorID:   actorID,
		Operation: "emergency_access.revoke",
	})
	if auditErr != nil {
		return errors.Join(ErrEmergencyAccessUnavailable, auditErr)
	}
	return nil
}

func (p *EmergencyAccessPolicy) Authorize(
	ctx context.Context,
	grant EmergencyAccessGrant,
	operation, credentialClass string,
) (EmergencyAccessResult, error) {
	result := EmergencyAccessResult{
		Decision: EmergencyAccessDenied, Reason: EmergencyAccessReasonInvalidGrant,
		GrantID: strings.TrimSpace(grant.ID), ActorID: strings.TrimSpace(grant.ActorID),
		Operation: strings.TrimSpace(operation), ExpiresAt: grant.ExpiresAt,
	}
	if p == nil {
		return result, ErrEmergencyAccessUnavailable
	}
	if err := p.validateGrant(grant); err != nil {
		return p.deny(ctx, result, EmergencyAccessReasonInvalidGrant, err)
	}
	if strings.TrimSpace(credentialClass) != p.credentialClass ||
		strings.TrimSpace(grant.CredentialClass) != p.credentialClass {
		return p.deny(ctx, result, EmergencyAccessReasonCredential, ErrEmergencyAccessDenied)
	}
	if _, ok := p.allowedOperations[result.Operation]; !ok ||
		!slices.Contains(grant.AllowedOperations, result.Operation) {
		return p.deny(ctx, result, EmergencyAccessReasonScope, ErrEmergencyAccessDenied)
	}
	now := p.now()
	if now.Before(grant.IssuedAt) || !now.Before(grant.ExpiresAt) {
		return p.deny(ctx, result, EmergencyAccessReasonExpired, ErrEmergencyAccessDenied)
	}
	revoked, err := p.revocations.EmergencyAccessRevoked(ctx, result.GrantID)
	if err != nil {
		return p.deny(ctx, result, EmergencyAccessReasonDependencyOutage, errors.Join(ErrEmergencyAccessUnavailable, err))
	}
	if revoked {
		return p.deny(ctx, result, EmergencyAccessReasonRevoked, ErrEmergencyAccessDenied)
	}
	result.Decision = EmergencyAccessAllowed
	result.Reason = EmergencyAccessReasonAllowed
	if err := p.audit(ctx, result); err != nil {
		result.Decision = EmergencyAccessDenied
		result.Reason = EmergencyAccessReasonAuditFailure
		return result, errors.Join(ErrEmergencyAccessUnavailable, err)
	}
	return result, nil
}

func (p *EmergencyAccessPolicy) validateGrant(grant EmergencyAccessGrant) error {
	actorID := strings.TrimSpace(grant.ActorID)
	if strings.TrimSpace(grant.ID) == "" || actorID == "" ||
		strings.TrimSpace(grant.Reason) == "" || grant.IssuedAt.IsZero() ||
		grant.ExpiresAt.IsZero() || !grant.IssuedAt.Before(grant.ExpiresAt) ||
		grant.ExpiresAt.Sub(grant.IssuedAt) > p.maxDuration {
		return ErrEmergencyAccessDenied
	}
	approvers := map[string]struct{}{}
	for _, approver := range grant.Approvers {
		approver = strings.TrimSpace(approver)
		if approver == "" || approver == actorID {
			return ErrEmergencyAccessDenied
		}
		if _, approved := p.approvedApprovers[approver]; !approved {
			return ErrEmergencyAccessDenied
		}
		approvers[approver] = struct{}{}
	}
	if len(approvers) < p.requiredApprovals || len(grant.AllowedOperations) == 0 {
		return ErrEmergencyAccessDenied
	}
	return nil
}

func (p *EmergencyAccessPolicy) deny(
	ctx context.Context,
	result EmergencyAccessResult,
	reason EmergencyAccessReason,
	cause error,
) (EmergencyAccessResult, error) {
	result.Decision = EmergencyAccessDenied
	result.Reason = reason
	if auditErr := p.audit(ctx, result); auditErr != nil {
		return result, errors.Join(cause, ErrEmergencyAccessUnavailable, auditErr)
	}
	return result, cause
}

func (p *EmergencyAccessPolicy) audit(ctx context.Context, result EmergencyAccessResult) error {
	return p.activitySink.Record(ctx, ActivityEvent{
		EventType: ActivityEventEmergencyAccess,
		Actor:     ActorRef{ID: result.ActorID, Type: "emergency_actor"},
		Metadata: map[string]any{
			"grant_id":               result.GrantID,
			"operation":              result.Operation,
			"decision":               result.Decision,
			"reason":                 result.Reason,
			"monitoring_destination": p.monitoringDestination,
		},
	})
}
