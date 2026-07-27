package auth_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	repository "github.com/goliatone/go-repository-bun"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

func TestInitializePasswordResetDoesNotExposeCredentialAndOnlyDeliversForKnownAccount(t *testing.T) {
	const email = "known@example.com"
	repo := &MockRepositoryManager{}
	users := &MockUsers{}
	resets := &MockPasswordResets{}
	userID := uuid.New()
	resetID := uuid.New()
	createdAt := time.Now().UTC()
	var delivered auth.PasswordResetDeliveryRequest

	repo.On("Users").Return(users).Once()
	repo.On("PasswordResets").Return(resets).Once()
	repo.On("RunInTx", mock.Anything, (*sql.TxOptions)(nil), mock.Anything).
		Return(nil).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(func(context.Context, bun.Tx) error)
			var tx bun.Tx
			require.NoError(t, fn(args.Get(0).(context.Context), tx))
		}).Once()
	users.On("GetByIdentifier", mock.Anything, email).
		Return(&auth.User{ID: userID, Email: email}, nil).Once()
	resets.On("CreateTx", mock.Anything, mock.Anything, mock.MatchedBy(func(record *auth.PasswordReset) bool {
		return record != nil &&
			record.UserID != nil &&
			*record.UserID == userID &&
			record.Email == email &&
			record.Status == auth.ResetRequestedStatus
	}), mock.Anything).
		Return(&auth.PasswordReset{
			ID:        resetID,
			UserID:    &userID,
			Email:     email,
			Status:    auth.ResetRequestedStatus,
			CreatedAt: &createdAt,
		}, nil).Once()

	var response *auth.InitializePasswordResetResponse
	handler := auth.NewInitializePasswordResetHandler(repo).
		WithDelivery(auth.PasswordResetDeliveryFunc(func(_ context.Context, req auth.PasswordResetDeliveryRequest) error {
			delivered = req
			return nil
		}))
	err := handler.Execute(context.Background(), auth.InitializePasswordResetMessage{
		Stage: auth.ResetInit,
		Email: email,
		OnResponse: func(resp *auth.InitializePasswordResetResponse) {
			response = resp
		},
	})

	require.NoError(t, err)
	require.NotNil(t, response)
	require.True(t, response.Success)
	require.Equal(t, auth.AccountVerification, response.Stage)
	require.Nil(t, response.Reset)
	require.Equal(t, email, delivered.Email)
	require.Equal(t, resetID.String(), delivered.Token.Reveal())
	require.True(t, delivered.ExpiresAt.After(time.Now()))
	repo.AssertExpectations(t)
	users.AssertExpectations(t)
	resets.AssertExpectations(t)
}

func TestInitializePasswordResetReturnsSamePublicResponseForUnknownAccount(t *testing.T) {
	const email = "unknown@example.com"
	repo := &MockRepositoryManager{}
	users := &MockUsers{}
	deliveries := 0

	repo.On("Users").Return(users).Once()
	repo.On("RunInTx", mock.Anything, (*sql.TxOptions)(nil), mock.Anything).
		Return(nil).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(func(context.Context, bun.Tx) error)
			var tx bun.Tx
			require.NoError(t, fn(args.Get(0).(context.Context), tx))
		}).Once()
	users.On("GetByIdentifier", mock.Anything, email).
		Return(nil, repository.NewRecordNotFound()).Once()

	var response *auth.InitializePasswordResetResponse
	handler := auth.NewInitializePasswordResetHandler(repo).
		WithDelivery(auth.PasswordResetDeliveryFunc(func(context.Context, auth.PasswordResetDeliveryRequest) error {
			deliveries++
			return nil
		}))
	err := handler.Execute(context.Background(), auth.InitializePasswordResetMessage{
		Stage: auth.ResetInit,
		Email: email,
		OnResponse: func(resp *auth.InitializePasswordResetResponse) {
			response = resp
		},
	})

	require.NoError(t, err)
	require.NotNil(t, response)
	require.True(t, response.Success)
	require.Equal(t, auth.AccountVerification, response.Stage)
	require.Nil(t, response.Reset)
	require.Zero(t, deliveries)
	repo.AssertExpectations(t)
	users.AssertExpectations(t)
}
