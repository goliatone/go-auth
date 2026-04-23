package auth_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/goliatone/go-auth"
	repository "github.com/goliatone/go-repository-bun"
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
	userRecord := &auth.User{
		ID: userID,
		Metadata: map[string]any{
			auth.TemporaryPasswordMetadataKey:          true,
			auth.PasswordChangeRequiredMetadataKey:     true,
			auth.TemporaryPasswordIssuedAtMetadataKey:  now.Add(-time.Hour).Format(time.RFC3339Nano),
			auth.TemporaryPasswordExpiresAtMetadataKey: now.Add(time.Hour).Format(time.RFC3339Nano),
		},
	}

	repo.On("PasswordResets").Return(resets).Twice()
	repo.On("Users").Return(users).Once()

	resets.On("GetByID", mock.Anything, event.Session, mock.Anything).
		Return(resetRecord, nil).Once()
	users.On("GetByIDTx", mock.Anything, mock.Anything, userID.String(), mock.Anything).
		Return(userRecord, nil).Once()
	users.On("ResetPasswordAndClearTemporaryPasswordTx", mock.Anything, mock.Anything, userID, mock.Anything).
		Return(nil).Once()
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

func TestFinalizePasswordResetHandler_AllowsNonTemporaryUserWithoutAtomicCleanup(t *testing.T) {
	ctx := context.Background()
	resets := &MockPasswordResets{}
	users := &legacyFinalizeUsersRepo{
		user: &auth.User{
			ID:    uuid.New(),
			Email: "user@example.com",
		},
	}
	userID := users.user.ID
	now := time.Now()
	repo := &legacyFinalizeRepositoryManager{
		users:  users,
		resets: resets,
	}

	handler := auth.NewFinalizePasswordResetHandler(repo).
		WithLogger(testLogger{})

	event := auth.FinalizePasswordResetMesasge{
		Session:  "session-token",
		Password: "password12345",
	}
	resetRecord := &auth.PasswordReset{
		ID:        uuid.New(),
		UserID:    &userID,
		Status:    auth.ResetRequestedStatus,
		CreatedAt: &now,
	}

	resets.On("GetByID", mock.Anything, event.Session, mock.Anything).
		Return(resetRecord, nil).Once()
	resets.On("UpdateTx", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(resetRecord, nil).Once()

	err := handler.Execute(ctx, event)

	require.NoError(t, err)
	require.True(t, users.resetPasswordTxCalled)
	require.False(t, users.resetAndClearCalled)
	require.Equal(t, userID, users.lastResetID)
	require.NotEmpty(t, users.lastResetHash)
	resets.AssertExpectations(t)
}

func TestFinalizePasswordResetHandler_RejectsTemporaryUserWithoutAtomicCleanup(t *testing.T) {
	ctx := context.Background()
	resets := &MockPasswordResets{}
	now := time.Now()
	userID := uuid.New()
	users := &legacyFinalizeUsersRepo{
		user: &auth.User{
			ID:    userID,
			Email: "user@example.com",
			Metadata: map[string]any{
				auth.TemporaryPasswordMetadataKey:          true,
				auth.PasswordChangeRequiredMetadataKey:     true,
				auth.TemporaryPasswordIssuedAtMetadataKey:  now.Add(-time.Hour).Format(time.RFC3339Nano),
				auth.TemporaryPasswordExpiresAtMetadataKey: now.Add(time.Hour).Format(time.RFC3339Nano),
			},
		},
	}
	repo := &legacyFinalizeRepositoryManager{
		users:  users,
		resets: resets,
	}

	handler := auth.NewFinalizePasswordResetHandler(repo).
		WithLogger(testLogger{})

	event := auth.FinalizePasswordResetMesasge{
		Session:  "session-token",
		Password: "password12345",
	}
	resetRecord := &auth.PasswordReset{
		ID:        uuid.New(),
		UserID:    &userID,
		Status:    auth.ResetRequestedStatus,
		CreatedAt: &now,
	}

	resets.On("GetByID", mock.Anything, event.Session, mock.Anything).
		Return(resetRecord, nil).Once()

	err := handler.Execute(ctx, event)

	require.Error(t, err)
	require.Contains(t, err.Error(), "temporary password reset cleanup")
	require.False(t, users.resetPasswordTxCalled)
	require.False(t, users.resetAndClearCalled)
	resets.AssertExpectations(t)
}

type legacyFinalizeUsersRepo struct {
	auth.Users
	user                  *auth.User
	resetPasswordTxCalled bool
	resetAndClearCalled   bool
	lastResetID           uuid.UUID
	lastResetHash         string
}

func (r *legacyFinalizeUsersRepo) GetByIDTx(_ context.Context, _ bun.IDB, id string, _ ...repository.SelectCriteria) (*auth.User, error) {
	if r.user == nil || r.user.ID.String() != id {
		return nil, repository.NewRecordNotFound()
	}
	return r.user, nil
}

func (r *legacyFinalizeUsersRepo) ResetPasswordTx(_ context.Context, _ bun.IDB, id uuid.UUID, passwordHash string) error {
	r.resetPasswordTxCalled = true
	r.lastResetID = id
	r.lastResetHash = passwordHash
	if r.user == nil || r.user.ID != id {
		return repository.NewRecordNotFound()
	}
	r.user.PasswordHash = passwordHash
	return nil
}

type legacyFinalizeRepositoryManager struct {
	auth.RepositoryManager
	users  auth.Users
	resets repository.Repository[*auth.PasswordReset]
}

func (r *legacyFinalizeRepositoryManager) RunInTx(ctx context.Context, _ *sql.TxOptions, f func(context.Context, bun.Tx) error) error {
	var tx bun.Tx
	return f(ctx, tx)
}

func (r *legacyFinalizeRepositoryManager) Users() auth.Users {
	return r.users
}

func (r *legacyFinalizeRepositoryManager) PasswordResets() repository.Repository[*auth.PasswordReset] {
	return r.resets
}
