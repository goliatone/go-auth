package auth

import (
	"context"
	"fmt"
	"time"

	goerrors "github.com/goliatone/go-errors"
)

const (
	textCodeInvalidTransition = "INVALID_USER_STATE_TRANSITION"
	textCodeTerminalState     = "TERMINAL_USER_STATE"
)

// ErrInvalidTransition is returned when a requested status change is not allowed.
var ErrInvalidTransition = goerrors.New("invalid user state transition", goerrors.CategoryValidation).
	WithTextCode(textCodeInvalidTransition).
	WithCode(goerrors.CodeBadRequest)

// ErrTerminalState is returned when attempting to move away from a terminal status (e.g., archived).
var ErrTerminalState = goerrors.New("user state is terminal", goerrors.CategoryConflict).
	WithTextCode(textCodeTerminalState).
	WithCode(goerrors.CodeConflict)

// ActorRef identifies who/what triggered a transition.
type ActorRef struct {
	ID   string
	Type string
}

// TransitionMetadata captures extra context for a transition.
type TransitionMetadata struct {
	Reason   string
	Metadata map[string]any
}

// TransitionContext is passed into hooks for additional processing.
type TransitionContext struct {
	Actor ActorRef
	User  *User
	From  UserStatus
	To    UserStatus
	Meta  TransitionMetadata
}

// TransitionHook is executed before or after a transition.
type TransitionHook func(ctx context.Context, tc TransitionContext) error

// TransitionHookPhase identifies whether a hook ran before or after persistence.
type TransitionHookPhase string

const (
	HookPhaseBefore TransitionHookPhase = "before_transition"
	HookPhaseAfter  TransitionHookPhase = "after_transition"
)

// TransitionOption customizes state machine behavior.
type TransitionOption func(*transitionOptions)

// UserStateMachine defines lifecycle operations for users.
type UserStateMachine interface {
	Transition(ctx context.Context, actor ActorRef, user *User, target UserStatus, opts ...TransitionOption) (*User, error)
	CurrentStatus(user *User) UserStatus
}

// HookErrorHandler handles errors surfaced by transition hooks.
type HookErrorHandler func(ctx context.Context, phase TransitionHookPhase, err error, tc TransitionContext) error

// StateMachineOption customizes state machine construction.
type StateMachineOption func(*userStateMachine)

// WithStateMachineClock injects a custom clock (useful for tests).
func WithStateMachineClock(clock func() time.Time) StateMachineOption {
	return func(sm *userStateMachine) {
		if clock != nil {
			sm.now = clock
		}
	}
}

// WithStateMachineActivitySink sets the ActivitySink used to publish lifecycle events.
func WithStateMachineActivitySink(sink ActivitySink) StateMachineOption {
	return func(sm *userStateMachine) {
		sm.activitySink = normalizeActivitySink(sink)
	}
}

// WithStateMachineHookErrorHandler overrides how hook failures are propagated.
// Provide a handler to convert hook errors into domain-specific responses,
// otherwise the default handler panics with guidance for developers.
func WithStateMachineHookErrorHandler(handler HookErrorHandler) StateMachineOption {
	return func(sm *userStateMachine) {
		if handler != nil {
			sm.hookErrorHandler = handler
		}
	}
}

// WithStateMachineLogger overrides the logger used for sink failures.
func WithStateMachineLogger(logger Logger) StateMachineOption {
	return func(sm *userStateMachine) {
		if logger != nil {
			sm.logger = logger
		}
	}
}

// WithTransitionReason sets the human-readable reason for the transition.
func WithTransitionReason(reason string) TransitionOption {
	return func(opts *transitionOptions) {
		opts.metadata.Reason = reason
	}
}

// WithTransitionMetadata merges metadata into the transition context.
func WithTransitionMetadata(metadata map[string]any) TransitionOption {
	return func(opts *transitionOptions) {
		if len(metadata) == 0 {
			return
		}
		if opts.metadata.Metadata == nil {
			opts.metadata.Metadata = make(map[string]any, len(metadata))
		}
		for k, v := range metadata {
			opts.metadata.Metadata[k] = v
		}
	}
}

// WithForceTransition bypasses validation rules (use sparingly).
func WithForceTransition() TransitionOption {
	return func(opts *transitionOptions) {
		opts.force = true
	}
}

// WithBeforeTransitionHook adds a hook executed before the status update.
func WithBeforeTransitionHook(h TransitionHook) TransitionOption {
	return func(opts *transitionOptions) {
		if h != nil {
			opts.beforeHooks = append(opts.beforeHooks, h)
		}
	}
}

// WithAfterTransitionHook adds a hook executed after the status update succeeds.
func WithAfterTransitionHook(h TransitionHook) TransitionOption {
	return func(opts *transitionOptions) {
		if h != nil {
			opts.afterHooks = append(opts.afterHooks, h)
		}
	}
}

// WithSuspensionTime overrides the timestamp recorded when entering the suspended state.
func WithSuspensionTime(t time.Time) TransitionOption {
	return func(opts *transitionOptions) {
		opts.suspensionTime = &t
	}
}

// NewUserStateMachine returns the default implementation backed by the provided repository.
func NewUserStateMachine(users Users, opts ...StateMachineOption) UserStateMachine {
	sm := &userStateMachine{
		users: users,
		transitions: map[UserStatus]map[UserStatus]struct{}{
			UserStatusPending: {
				UserStatusActive:   {},
				UserStatusDisabled: {},
			},
			UserStatusActive: {
				UserStatusSuspended: {},
				UserStatusDisabled:  {},
				UserStatusArchived:  {},
			},
			UserStatusSuspended: {
				UserStatusActive:   {},
				UserStatusDisabled: {},
			},
			UserStatusDisabled: {
				UserStatusArchived: {},
			},
		},
		now:          time.Now,
		activitySink: noopActivitySink{},
		logger:       defLogger{},
		hookErrorHandler: func(ctx context.Context, phase TransitionHookPhase, err error, tc TransitionContext) error {
			return defaultHookErrorHandler(ctx, phase, err, tc)
		},
	}

	for _, opt := range opts {
		if opt != nil {
			opt(sm)
		}
	}

	return sm
}

type userStateMachine struct {
	users            Users
	transitions      map[UserStatus]map[UserStatus]struct{}
	now              func() time.Time
	activitySink     ActivitySink
	logger           Logger
	hookErrorHandler HookErrorHandler
}

type transitionOptions struct {
	metadata       TransitionMetadata
	force          bool
	beforeHooks    []TransitionHook
	afterHooks     []TransitionHook
	suspensionTime *time.Time
}

func (o *transitionOptions) cloneMetadata() TransitionMetadata {
	var cloned map[string]any
	if len(o.metadata.Metadata) > 0 {
		cloned = make(map[string]any, len(o.metadata.Metadata))
		for k, v := range o.metadata.Metadata {
			cloned[k] = v
		}
	}

	return TransitionMetadata{
		Reason:   o.metadata.Reason,
		Metadata: cloned,
	}
}

func (sm *userStateMachine) Transition(ctx context.Context, actor ActorRef, user *User, target UserStatus, opts ...TransitionOption) (*User, error) {
	if user == nil {
		return nil, ErrInvalidTransition.WithMetadata(map[string]any{
			"target": target,
			"reason": "user is nil",
		})
	}

	user.EnsureStatus()
	from := user.Status
	if target == "" {
		return nil, ErrInvalidTransition.WithMetadata(map[string]any{
			"reason": "target status is empty",
		})
	}

	if from == target {
		return user, nil
	}

	options := sm.buildTransitionOptions(opts...)

	if from == UserStatusArchived && !options.force {
		return nil, ErrTerminalState.WithMetadata(map[string]any{
			"from": from,
			"to":   target,
		})
	}

	if !options.force && !sm.canTransition(from, target) {
		return nil, ErrInvalidTransition.WithMetadata(map[string]any{
			"from": from,
			"to":   target,
		})
	}

	ctxData := TransitionContext{
		Actor: actor,
		User:  user,
		From:  from,
		To:    target,
		Meta:  options.cloneMetadata(),
	}

	if err := sm.runHooks(ctx, options.beforeHooks, ctxData, HookPhaseBefore); err != nil {
		return nil, err
	}

	statusOpts, chosenSuspension := sm.buildStatusOptions(user, from, target, options)

	updated, err := sm.users.UpdateStatus(ctx, user.ID, target, statusOpts...)
	if err != nil {
		return nil, err
	}

	sm.applyUpdates(user, updated, target, from, chosenSuspension)

	if err := sm.runHooks(ctx, options.afterHooks, ctxData, HookPhaseAfter); err != nil {
		return nil, err
	}

	sm.recordActivity(ctx, ActivityEvent{
		EventType:  ActivityEventUserStatusChanged,
		Actor:      actor,
		UserID:     user.ID.String(),
		FromStatus: from,
		ToStatus:   target,
		Metadata:   sm.transitionMetadata(ctxData.Meta),
	})

	return user, nil
}

func (sm *userStateMachine) CurrentStatus(user *User) UserStatus {
	if user == nil {
		return ""
	}
	user.EnsureStatus()
	return user.Status
}

func (sm *userStateMachine) runHooks(ctx context.Context, hooks []TransitionHook, data TransitionContext, phase TransitionHookPhase) error {
	for _, hook := range hooks {
		if hook == nil {
			continue
		}
		if err := hook(ctx, data); err != nil {
			if sm.hookErrorHandler == nil {
				return err
			}
			return sm.hookErrorHandler(ctx, phase, err, data)
		}
	}
	return nil
}

func (sm *userStateMachine) canTransition(from, to UserStatus) bool {
	if allowed, ok := sm.transitions[from]; ok {
		_, exists := allowed[to]
		return exists
	}
	return false
}

func (sm *userStateMachine) buildTransitionOptions(opts ...TransitionOption) *transitionOptions {
	options := &transitionOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}
	return options
}

func (sm *userStateMachine) buildStatusOptions(user *User, from, to UserStatus, opts *transitionOptions) ([]StatusUpdateOption, *time.Time) {
	statusOpts := []StatusUpdateOption{}
	var suspensionTime *time.Time

	if to == UserStatusSuspended {
		switch {
		case opts.suspensionTime != nil:
			suspensionTime = opts.suspensionTime
		case user.SuspendedAt != nil:
			suspensionTime = user.SuspendedAt
		default:
			now := sm.now()
			suspensionTime = &now
		}
		statusOpts = append(statusOpts, WithSuspendedAt(suspensionTime))
	} else if from == UserStatusSuspended && user.SuspendedAt != nil {
		statusOpts = append(statusOpts, WithSuspendedAt(nil))
	}

	return statusOpts, suspensionTime
}

func defaultHookErrorHandler(_ context.Context, phase TransitionHookPhase, err error, tc TransitionContext) error {
	panic(fmt.Sprintf(
		"go-auth: %s transition hook failed: %v\nUserID: %s from=%s to=%s reason=%s\nProvide auth.WithStateMachineHookErrorHandler to customize error handling in production.",
		phase,
		err,
		tc.User.ID,
		tc.From,
		tc.To,
		tc.Meta.Reason,
	))
}

func (sm *userStateMachine) applyUpdates(user, updated *User, target, from UserStatus, suspensionTime *time.Time) {
	if updated != nil {
		if updated.Status != "" {
			user.Status = updated.Status
		} else {
			user.Status = target
		}
		user.SuspendedAt = updated.SuspendedAt
		return
	}

	user.Status = target
	if target == UserStatusSuspended {
		user.SuspendedAt = suspensionTime
	} else if from == UserStatusSuspended {
		user.SuspendedAt = nil
	}
}

func (sm *userStateMachine) recordActivity(ctx context.Context, event ActivityEvent) {
	if event.Actor == (ActorRef{}) {
		event.Actor = ActorRef{Type: "system"}
	}

	if event.OccurredAt.IsZero() {
		event.OccurredAt = sm.now()
	}

	sink := normalizeActivitySink(sm.activitySink)
	if err := sink.Record(ctx, event); err != nil {
		sm.logger.Warn("state machine activity sink error: %v", err)
	}
}

func (sm *userStateMachine) transitionMetadata(meta TransitionMetadata) map[string]any {
	if meta.Reason == "" && len(meta.Metadata) == 0 {
		return nil
	}

	result := map[string]any{}
	if meta.Reason != "" {
		result["reason"] = meta.Reason
	}
	for k, v := range meta.Metadata {
		result[k] = v
	}
	return result
}
