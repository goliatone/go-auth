package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/goliatone/go-auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUserStateMachineTransitionToSuspendedSetsTimestamp(t *testing.T) {
	repo := &MockUsers{}
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	user := &auth.User{
		ID:     uuid.New(),
		Status: auth.UserStatusActive,
	}

	expected := &auth.User{
		ID:          user.ID,
		Status:      auth.UserStatusSuspended,
		SuspendedAt: &now,
	}

	repo.On("UpdateStatus", mock.Anything, user.ID, auth.UserStatusSuspended, mock.Anything).
		Return(expected, nil).Once()

	sm := auth.NewUserStateMachine(repo, auth.WithStateMachineClock(func() time.Time { return now }))

	result, err := sm.Transition(context.Background(), auth.ActorRef{ID: "admin"}, user, auth.UserStatusSuspended)
	require.NoError(t, err)
	assert.True(t, result.IsSuspended())
	require.NotNil(t, result.SuspendedAt)
	assert.Equal(t, now, result.SuspendedAt.UTC())
	repo.AssertExpectations(t)
}

func TestUserStateMachineRejectsInvalidTransition(t *testing.T) {
	repo := &MockUsers{}
	user := &auth.User{
		ID:     uuid.New(),
		Status: auth.UserStatusPending,
	}

	sm := auth.NewUserStateMachine(repo)

	_, err := sm.Transition(context.Background(), auth.ActorRef{}, user, auth.UserStatusSuspended)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrInvalidTransition)
	repo.AssertNotCalled(t, "UpdateStatus", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestUserStateMachineForceTransitionBypassesValidation(t *testing.T) {
	repo := &MockUsers{}
	user := &auth.User{
		ID:     uuid.New(),
		Status: auth.UserStatusPending,
	}

	repo.On("UpdateStatus", mock.Anything, user.ID, auth.UserStatusSuspended, mock.Anything).
		Return(&auth.User{ID: user.ID, Status: auth.UserStatusSuspended}, nil).Once()

	sm := auth.NewUserStateMachine(repo)

	result, err := sm.Transition(
		context.Background(),
		auth.ActorRef{},
		user,
		auth.UserStatusSuspended,
		auth.WithForceTransition(),
	)
	require.NoError(t, err)
	assert.True(t, result.IsSuspended())
	repo.AssertExpectations(t)
}

func TestUserStateMachineLeavingSuspendedClearsTimestamp(t *testing.T) {
	repo := &MockUsers{}
	now := time.Now()
	user := &auth.User{
		ID:          uuid.New(),
		Status:      auth.UserStatusSuspended,
		SuspendedAt: &now,
	}

	repo.On("UpdateStatus", mock.Anything, user.ID, auth.UserStatusActive, mock.Anything).
		Return(&auth.User{ID: user.ID, Status: auth.UserStatusActive}, nil).Once()

	sm := auth.NewUserStateMachine(repo)

	result, err := sm.Transition(context.Background(), auth.ActorRef{}, user, auth.UserStatusActive)
	require.NoError(t, err)
	assert.True(t, result.IsActive())
	assert.Nil(t, result.SuspendedAt)
	repo.AssertExpectations(t)
}

func TestUserStateMachineRunsHooksWithMetadata(t *testing.T) {
	repo := &MockUsers{}
	user := &auth.User{
		ID:     uuid.New(),
		Status: auth.UserStatusActive,
	}

	ts := time.Date(2024, 6, 1, 15, 0, 0, 0, time.UTC)

	repo.On("UpdateStatus", mock.Anything, user.ID, auth.UserStatusSuspended, mock.Anything).
		Return(&auth.User{ID: user.ID, Status: auth.UserStatusSuspended, SuspendedAt: &ts}, nil).Once()

	var beforeCalled, afterCalled bool
	var reasonSeen string
	var metadataSeen map[string]any

	before := func(ctx context.Context, tc auth.TransitionContext) error {
		beforeCalled = true
		reasonSeen = tc.Meta.Reason
		metadataSeen = tc.Meta.Metadata
		return nil
	}
	after := func(ctx context.Context, tc auth.TransitionContext) error {
		afterCalled = true
		return nil
	}

	sm := auth.NewUserStateMachine(repo, auth.WithStateMachineClock(func() time.Time { return ts }))

	metadata := map[string]any{"ticket": "123"}

	_, err := sm.Transition(
		context.Background(),
		auth.ActorRef{ID: "admin"},
		user,
		auth.UserStatusSuspended,
		auth.WithTransitionReason("policy"),
		auth.WithTransitionMetadata(metadata),
		auth.WithBeforeTransitionHook(before),
		auth.WithAfterTransitionHook(after),
	)
	require.NoError(t, err)
	assert.True(t, beforeCalled)
	assert.True(t, afterCalled)
	assert.Equal(t, "policy", reasonSeen)
	require.NotNil(t, metadataSeen)
	assert.Equal(t, "123", metadataSeen["ticket"])
	repo.AssertExpectations(t)
}

func TestUserStateMachineEmitsActivityEvent(t *testing.T) {
	repo := &MockUsers{}
	sink := &MockActivitySink{}
	now := time.Date(2024, 6, 2, 9, 0, 0, 0, time.UTC)
	user := &auth.User{
		ID:     uuid.New(),
		Status: auth.UserStatusActive,
	}

	repo.On("UpdateStatus", mock.Anything, user.ID, auth.UserStatusSuspended, mock.Anything).
		Return(&auth.User{ID: user.ID, Status: auth.UserStatusSuspended}, nil).Once()

	sink.On("Record", mock.Anything, mock.MatchedBy(func(evt auth.ActivityEvent) bool {
		return evt.EventType == auth.ActivityEventUserStatusChanged &&
			evt.UserID == user.ID.String() &&
			evt.FromStatus == auth.UserStatusActive &&
			evt.ToStatus == auth.UserStatusSuspended
	})).Return(nil).Once()

	sm := auth.NewUserStateMachine(
		repo,
		auth.WithStateMachineClock(func() time.Time { return now }),
		auth.WithStateMachineActivitySink(sink),
	)

	_, err := sm.Transition(context.Background(), auth.ActorRef{ID: "admin"}, user, auth.UserStatusSuspended)
	require.NoError(t, err)

	repo.AssertExpectations(t)
	sink.AssertExpectations(t)
}
