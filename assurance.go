package auth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

// AssuranceLevel is a provider-neutral ordered authentication assurance level.
type AssuranceLevel string

const (
	AssuranceUnknown AssuranceLevel = "unknown"
	AssuranceAAL1    AssuranceLevel = "aal1"
	AssuranceAAL2    AssuranceLevel = "aal2"
)

// ParseAssuranceLevel parses only supported provider-neutral values.
func ParseAssuranceLevel(value string) (AssuranceLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return AssuranceUnknown, ErrAssuranceMissing
	case string(AssuranceAAL1):
		return AssuranceAAL1, nil
	case string(AssuranceAAL2):
		return AssuranceAAL2, nil
	default:
		return AssuranceUnknown, ErrAssuranceUnknown
	}
}

func (l AssuranceLevel) validRequirement() bool {
	return l == AssuranceAAL1 || l == AssuranceAAL2
}

func (l AssuranceLevel) rank() int {
	switch l {
	case AssuranceAAL1:
		return 1
	case AssuranceAAL2:
		return 2
	default:
		return 0
	}
}

// Meets reports whether a known level satisfies another known level.
func (l AssuranceLevel) Meets(required AssuranceLevel) bool {
	return l.validRequirement() && required.validRequirement() && l.rank() >= required.rank()
}

// AssuranceContext contains normalized, non-secret authentication evidence.
type AssuranceContext struct {
	Level            AssuranceLevel
	Methods          []string
	AuthenticationAt time.Time
}

func (c AssuranceContext) clone() AssuranceContext {
	c.Methods = slices.Clone(c.Methods)
	return c
}

type assuranceContextKey struct{}

// WithAssuranceContext stores isolated normalized assurance evidence.
func WithAssuranceContext(ctx context.Context, assurance AssuranceContext) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, assuranceContextKey{}, assurance.clone())
}

// AssuranceFromContext returns explicit assurance evidence or derives it from
// the normalized provider-session principal.
func AssuranceFromContext(ctx context.Context) (AssuranceContext, error) {
	if ctx == nil {
		return AssuranceContext{}, ErrAssuranceMissing
	}
	if assurance, ok := ctx.Value(assuranceContextKey{}).(AssuranceContext); ok {
		return assurance.clone(), nil
	}
	if providerSession, ok := ProviderSessionFromContext(ctx); ok {
		level, err := ParseAssuranceLevel(providerSession.Principal.AssuranceLevel())
		if err != nil {
			return AssuranceContext{}, err
		}
		return AssuranceContext{
			Level:            level,
			Methods:          providerSession.Principal.AssuranceMethods(),
			AuthenticationAt: providerSession.Principal.AuthenticationAt(),
		}, nil
	}
	return AssuranceContext{}, ErrAssuranceMissing
}

type AssuranceDecision string

const (
	AssuranceAllowed        AssuranceDecision = "allowed"
	AssuranceDenied         AssuranceDecision = "denied"
	AssuranceStepUpRequired AssuranceDecision = "step_up_required"
)

type AssuranceReason string

const (
	AssuranceReasonSatisfied    AssuranceReason = "satisfied"
	AssuranceReasonMissing      AssuranceReason = "missing"
	AssuranceReasonUnknown      AssuranceReason = "unknown"
	AssuranceReasonInsufficient AssuranceReason = "insufficient"
	AssuranceReasonStale        AssuranceReason = "stale"
	AssuranceReasonInvalid      AssuranceReason = "invalid_requirement"
)

// AssuranceRequirement is policy input for a single operation.
type AssuranceRequirement struct {
	Level                AssuranceLevel
	MaxAuthenticationAge time.Duration
	Operation            string
	AllowStepUp          bool
}

// AssuranceResult is safe to log and contains no provider tokens.
type AssuranceResult struct {
	Decision         AssuranceDecision
	Reason           AssuranceReason
	Required         AssuranceLevel
	Current          AssuranceLevel
	Methods          []string
	AuthenticationAt time.Time
	Operation        string
}

// AssuranceGuard evaluates assurance and emits denial/step-up audit events.
type AssuranceGuard struct {
	Now          func() time.Time
	ActivitySink ActivitySink
}

// RequireAssurance performs the compatibility-friendly level-only check.
func RequireAssurance(ctx context.Context, level AssuranceLevel) (AssuranceResult, error) {
	return (AssuranceGuard{}).Require(ctx, AssuranceRequirement{Level: level})
}

func (g AssuranceGuard) Require(ctx context.Context, requirement AssuranceRequirement) (AssuranceResult, error) {
	result := AssuranceResult{
		Decision:  AssuranceDenied,
		Reason:    AssuranceReasonInvalid,
		Required:  requirement.Level,
		Operation: strings.TrimSpace(requirement.Operation),
	}
	if !requirement.Level.validRequirement() || requirement.MaxAuthenticationAge < 0 {
		g.emit(ctx, result, ErrAssuranceUnknown)
		return result, ErrAssuranceUnknown
	}

	assurance, err := AssuranceFromContext(ctx)
	if err != nil {
		switch {
		case errors.Is(err, ErrAssuranceMissing):
			result.Reason = AssuranceReasonMissing
		default:
			result.Reason = AssuranceReasonUnknown
		}
		return g.denyOrStepUp(ctx, requirement, result, err)
	}
	result.Current = assurance.Level
	result.Methods = slices.Clone(assurance.Methods)
	result.AuthenticationAt = assurance.AuthenticationAt

	if !assurance.Level.validRequirement() {
		result.Reason = AssuranceReasonUnknown
		g.emit(ctx, result, ErrAssuranceUnknown)
		return result, ErrAssuranceUnknown
	}
	if !assurance.Level.Meets(requirement.Level) {
		result.Reason = AssuranceReasonInsufficient
		return g.denyOrStepUp(ctx, requirement, result, ErrAssuranceInsufficient)
	}
	if requirement.MaxAuthenticationAge > 0 {
		now := time.Now()
		if g.Now != nil {
			now = g.Now()
		}
		if assurance.AuthenticationAt.IsZero() ||
			assurance.AuthenticationAt.After(now) ||
			now.Sub(assurance.AuthenticationAt) > requirement.MaxAuthenticationAge {
			result.Reason = AssuranceReasonStale
			return g.denyOrStepUp(ctx, requirement, result, ErrAssuranceStale)
		}
	}
	result.Decision = AssuranceAllowed
	result.Reason = AssuranceReasonSatisfied
	return result, nil
}

func (g AssuranceGuard) denyOrStepUp(
	ctx context.Context,
	requirement AssuranceRequirement,
	result AssuranceResult,
	cause error,
) (AssuranceResult, error) {
	if requirement.AllowStepUp &&
		(result.Reason == AssuranceReasonMissing ||
			result.Reason == AssuranceReasonInsufficient ||
			result.Reason == AssuranceReasonStale) {
		result.Decision = AssuranceStepUpRequired
		g.emit(ctx, result, ErrAssuranceStepUpRequired)
		return result, errors.Join(ErrAssuranceStepUpRequired, cause)
	}
	g.emit(ctx, result, cause)
	return result, cause
}

func (g AssuranceGuard) emit(ctx context.Context, result AssuranceResult, err error) {
	if g.ActivitySink == nil {
		return
	}
	eventType := ActivityEventAssuranceDenied
	if result.Decision == AssuranceStepUpRequired {
		eventType = ActivityEventAssuranceStepUp
	}
	metadata := map[string]any{
		"decision":  result.Decision,
		"reason":    result.Reason,
		"required":  result.Required,
		"current":   result.Current,
		"operation": result.Operation,
	}
	if err != nil {
		metadata["error"] = "assurance requirement not satisfied"
	}
	_ = g.ActivitySink.Record(ctx, ActivityEvent{
		EventType: eventType,
		Metadata:  metadata,
	})
}
