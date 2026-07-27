package auth

import (
	"context"
	"time"
)

// ActivityEventType enumerates supported activity categories.
type ActivityEventType string

const (
	ActivityEventUserStatusChanged        ActivityEventType = "user.status.changed"
	ActivityEventLoginSuccess             ActivityEventType = "auth.login.success"
	ActivityEventLoginFailure             ActivityEventType = "auth.login.failure"
	ActivityEventSocialLogin              ActivityEventType = "auth.social.login"
	ActivityEventSSOLoginSuccess          ActivityEventType = "auth.sso.login.success"
	ActivityEventSSOLoginFailure          ActivityEventType = "auth.sso.login.failure"
	ActivityEventSSOLinkAutomatic         ActivityEventType = "auth.sso.link.automatic"
	ActivityEventSSOLinkManual            ActivityEventType = "auth.sso.link.manual"
	ActivityEventSSOLinkRejected          ActivityEventType = "auth.sso.link.rejected"
	ActivityEventSSOUnlink                ActivityEventType = "auth.sso.unlink"
	ActivityEventSSOLogout                ActivityEventType = "auth.sso.logout"
	ActivityEventProviderSessionCreated   ActivityEventType = "auth.provider_session.created"
	ActivityEventProviderSessionRefreshed ActivityEventType = "auth.provider_session.refreshed"
	ActivityEventProviderSessionUncertain ActivityEventType = "auth.provider_session.uncertain"
	ActivityEventProviderSessionRevoked   ActivityEventType = "auth.provider_session.revoked"
	ActivityEventProviderTokenAccessed    ActivityEventType = "auth.provider_token.accessed"
	ActivityEventProviderInvite           ActivityEventType = "auth.provider.identity.invite"
	ActivityEventProviderRecovery         ActivityEventType = "auth.provider.identity.recovery"
	ActivityEventProviderAccountSuspend   ActivityEventType = "auth.provider.account.suspend"
	ActivityEventProviderAccountActivate  ActivityEventType = "auth.provider.account.activate"
	ActivityEventProviderAccountState     ActivityEventType = "auth.provider.account.state"
	ActivityEventProviderFactorList       ActivityEventType = "auth.provider.factor.list"
	ActivityEventProviderFactorRemove     ActivityEventType = "auth.provider.factor.remove"
	ActivityEventProviderAuthDetails      ActivityEventType = "auth.provider.authorization.details"
	ActivityEventProviderAuthApprove      ActivityEventType = "auth.provider.authorization.approve"
	ActivityEventProviderAuthDeny         ActivityEventType = "auth.provider.authorization.deny"
	ActivityEventImpersonationSuccess     ActivityEventType = "auth.impersonation.success"
	ActivityEventImpersonationFailure     ActivityEventType = "auth.impersonation.failure"
	ActivityEventPasswordResetSuccess     ActivityEventType = "auth.password.reset"
	ActivityEventAssuranceDenied          ActivityEventType = "auth.assurance.denied"
	ActivityEventAssuranceStepUp          ActivityEventType = "auth.assurance.step_up"
	ActivityEventAuthorizationFreshness   ActivityEventType = "auth.authorization.freshness"
	ActivityEventFreshnessInvalidation    ActivityEventType = "auth.freshness.invalidation"
	ActivityEventEmergencyAccess          ActivityEventType = "auth.emergency_access"
)

// ActivityEvent captures audit-friendly information about an action.
type ActivityEvent struct {
	EventType  ActivityEventType
	Actor      ActorRef
	UserID     string
	FromStatus UserStatus
	ToStatus   UserStatus
	Metadata   map[string]any
	OccurredAt time.Time
}

// ActivitySink consumes activity events for auditing/telemetry purposes.
type ActivitySink interface {
	Record(ctx context.Context, event ActivityEvent) error
}

// ActivitySinkFunc adapts a function to the ActivitySink interface.
type ActivitySinkFunc func(ctx context.Context, event ActivityEvent) error

// Record implements ActivitySink.
func (f ActivitySinkFunc) Record(ctx context.Context, event ActivityEvent) error {
	if f == nil {
		return nil
	}
	return f(ctx, event)
}

type noopActivitySink struct{}

func (noopActivitySink) Record(context.Context, ActivityEvent) error {
	return nil
}

func normalizeActivitySink(s ActivitySink) ActivitySink {
	if s == nil {
		return noopActivitySink{}
	}
	return s
}
