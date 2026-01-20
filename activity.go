package auth

import (
	"context"
	"time"
)

// ActivityEventType enumerates supported activity categories.
type ActivityEventType string

const (
	ActivityEventUserStatusChanged    ActivityEventType = "user.status.changed"
	ActivityEventLoginSuccess         ActivityEventType = "auth.login.success"
	ActivityEventLoginFailure         ActivityEventType = "auth.login.failure"
	ActivityEventSocialLogin          ActivityEventType = "auth.social.login"
	ActivityEventImpersonationSuccess ActivityEventType = "auth.impersonation.success"
	ActivityEventImpersonationFailure ActivityEventType = "auth.impersonation.failure"
	ActivityEventPasswordResetSuccess ActivityEventType = "auth.password.reset"
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
