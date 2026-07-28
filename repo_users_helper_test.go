package auth

import (
	"context"
	"testing"

	gerrors "github.com/goliatone/go-errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubStateMachine struct {
	lastTarget UserStatus
	err        error
}

func TestPrepareUserDefaultsExternalIdentityPair(t *testing.T) {
	t.Parallel()

	record := &User{ExternalID: " subject ", ExternalIDProvider: " oidc "}
	require.NoError(t, prepareUserDefaults(record))
	assert.Equal(t, "subject", record.ExternalID)
	assert.Equal(t, "oidc", record.ExternalIDProvider)
	assert.NotEqual(t, uuid.Nil, record.ID)

	invalid := &User{ExternalID: "subject"}
	err := prepareUserDefaults(invalid)
	require.Error(t, err)
	var rich *gerrors.Error
	require.ErrorAs(t, err, &rich)
	assert.Equal(t, gerrors.CategoryValidation, rich.Category)
	assert.Equal(t, gerrors.CodeBadRequest, rich.Code)
	assert.Equal(t, "USER_EXTERNAL_IDENTITY_INVALID", rich.TextCode)
	assert.Equal(t, uuid.Nil, invalid.ID, "invalid records must not be mutated with generated IDs")

	providerOnly := &User{ExternalIDProvider: "oidc"}
	require.Error(t, prepareUserDefaults(providerOnly))
	assert.Equal(t, uuid.Nil, providerOnly.ID, "invalid records must not be mutated with generated IDs")
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
