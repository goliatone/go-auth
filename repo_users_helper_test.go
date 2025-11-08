package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type stubStateMachine struct {
	lastTarget UserStatus
	err        error
}

func (s *stubStateMachine) Transition(ctx context.Context, actor ActorRef, user *User, target UserStatus, opts ...TransitionOption) (*User, error) {
	s.lastTarget = target
	return user, s.err
}

func (s *stubStateMachine) CurrentStatus(user *User) UserStatus {
	if user == nil {
		return ""
	}
	return user.Status
}

func TestUsersLifecycleHelpers(t *testing.T) {
	t.Parallel()

	stub := &stubStateMachine{}
	repo := &users{
		stateMachine: stub,
	}

	actor := ActorRef{ID: "admin"}
	u := &User{Status: UserStatusActive}

	_, err := repo.Suspend(context.Background(), actor, u)
	assert.NoError(t, err)
	assert.Equal(t, UserStatusSuspended, stub.lastTarget)

	_, err = repo.Reinstate(context.Background(), actor, u)
	assert.NoError(t, err)
	assert.Equal(t, UserStatusActive, stub.lastTarget)
}
