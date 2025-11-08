package auth_test

import (
	"context"
	"testing"

	"github.com/goliatone/go-auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type capturingSink struct {
	events []auth.ActivityEvent
}

func (c *capturingSink) Record(ctx context.Context, evt auth.ActivityEvent) error {
	c.events = append(c.events, evt)
	return nil
}

func TestLifecycleActivityAndClaimsIntegration(t *testing.T) {
	ctx := context.Background()
	sink := &capturingSink{}
	repo := new(MockUsers)

	userID := uuid.New()
	user := &auth.User{ID: userID, Status: auth.UserStatusActive}

	repo.On("UpdateStatus", ctx, userID, auth.UserStatusSuspended, mock.Anything).
		Return(&auth.User{ID: userID, Status: auth.UserStatusSuspended}, nil).Once()
	repo.On("UpdateStatus", ctx, userID, auth.UserStatusActive, mock.Anything).
		Return(&auth.User{ID: userID, Status: auth.UserStatusActive}, nil).Once()

	stateMachine := auth.NewUserStateMachine(repo, auth.WithStateMachineActivitySink(sink))

	var err error
	user, err = stateMachine.Transition(ctx, auth.ActorRef{ID: "system"}, user, auth.UserStatusSuspended)
	require.NoError(t, err)

	mockProvider := new(MockIdentityProvider)
	mockConfig := newMockConfig()

	decorator := auth.ClaimsDecoratorFunc(func(ctx context.Context, identity auth.Identity, claims *auth.JWTClaims) error {
		if claims.Metadata == nil {
			claims.Metadata = map[string]any{}
		}
		claims.Metadata["integration"] = "ok"
		if claims.Resources == nil {
			claims.Resources = map[string]string{}
		}
		claims.Resources["workspace"] = "editor"
		return nil
	})

	authenticator := auth.NewAuthenticator(mockProvider, mockConfig).
		WithActivitySink(sink).
		WithClaimsDecorator(decorator)

	identitySuspended := TestIdentity{
		id:       userID.String(),
		username: "integration-user",
		email:    "integration@example.com",
		role:     "admin",
		status:   auth.UserStatusSuspended,
	}

	mockProvider.On("VerifyIdentity", ctx, identitySuspended.email, "password123").
		Return(identitySuspended, nil).Once()

	token, err := authenticator.Login(ctx, identitySuspended.email, "password123")
	require.ErrorIs(t, err, auth.ErrUserSuspended)
	require.Empty(t, token)

	user, err = stateMachine.Transition(ctx, auth.ActorRef{ID: "system"}, user, auth.UserStatusActive)
	require.NoError(t, err)

	identityActive := identitySuspended
	identityActive.status = auth.UserStatusActive

	mockProvider.On("VerifyIdentity", ctx, identityActive.email, "password123").
		Return(identityActive, nil).Once()

	token, err = authenticator.Login(ctx, identityActive.email, "password123")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claimsAny, err := authenticator.TokenService().Validate(token)
	require.NoError(t, err)

	jwtClaims, ok := claimsAny.(*auth.JWTClaims)
	require.True(t, ok)
	assert.Equal(t, "ok", jwtClaims.Metadata["integration"])
	assert.Equal(t, "editor", jwtClaims.Resources["workspace"])

	require.Len(t, sink.events, 4)
	assert.Equal(t, auth.ActivityEventUserStatusChanged, sink.events[0].EventType)
	assert.Equal(t, auth.UserStatusSuspended, sink.events[0].ToStatus)
	assert.Equal(t, auth.ActivityEventLoginFailure, sink.events[1].EventType)
	assert.Equal(t, auth.ActivityEventUserStatusChanged, sink.events[2].EventType)
	assert.Equal(t, auth.UserStatusActive, sink.events[2].ToStatus)
	assert.Equal(t, auth.ActivityEventLoginSuccess, sink.events[3].EventType)

	mockProvider.AssertExpectations(t)
	repo.AssertExpectations(t)
}
