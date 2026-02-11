package auth_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/goliatone/go-auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

type testLogger struct{}

func (testLogger) Trace(string, ...any) {}
func (testLogger) Debug(string, ...any) {}
func (testLogger) Info(string, ...any)  {}
func (testLogger) Warn(string, ...any)  {}
func (testLogger) Error(string, ...any) {}
func (testLogger) Fatal(string, ...any) {}
func (testLogger) WithContext(context.Context) auth.Logger {
	return testLogger{}
}

func TestFinalizePasswordResetHandlerEmitsActivity(t *testing.T) {
	ctx := context.Background()
	repo := &MockRepositoryManager{}
	users := &MockUsers{}
	resets := &MockPasswordResets{}
	sink := &MockActivitySink{}

	handler := auth.NewFinalizePasswordResetHandler(repo).
		WithActivitySink(sink).
		WithLogger(testLogger{})

	event := auth.FinalizePasswordResetMesasge{
		Session:  "session-token",
		Password: "password12345",
	}

	userID := uuid.New()
	now := time.Now()

	resetRecord := &auth.PasswordReset{
		ID:        uuid.New(),
		UserID:    &userID,
		Status:    auth.ResetRequestedStatus,
		CreatedAt: &now,
	}

	repo.On("PasswordResets").Return(resets).Twice()
	repo.On("Users").Return(users).Once()

	resets.On("GetByID", mock.Anything, event.Session, mock.Anything).
		Return(resetRecord, nil).Once()
	users.On("RawTx", mock.Anything, mock.Anything, auth.ResetUserPasswordSQL, mock.Anything).
		Return([]*auth.User{{}}, nil).Once()
	resets.On("UpdateTx", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(resetRecord, nil).Once()

	repo.On("RunInTx", mock.Anything, (*sql.TxOptions)(nil), mock.Anything).
		Return(nil).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(func(context.Context, bun.Tx) error)
			var tx bun.Tx
			require.NoError(t, fn(args.Get(0).(context.Context), tx))
		}).Once()

	sink.On("Record", mock.Anything, mock.MatchedBy(func(evt auth.ActivityEvent) bool {
		return evt.EventType == auth.ActivityEventPasswordResetSuccess &&
			evt.UserID == userID.String()
	})).Return(nil).Once()

	err := handler.Execute(ctx, event)
	require.NoError(t, err)

	repo.AssertExpectations(t)
	users.AssertExpectations(t)
	resets.AssertExpectations(t)
	sink.AssertExpectations(t)
}
