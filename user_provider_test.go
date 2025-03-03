package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goliatone/go-auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUserProviderVerifyIdentity(t *testing.T) {
	ctx := context.Background()
	mockTracker := new(MockUserTracker)

	provider := auth.NewUserProvider(mockTracker)

	t.Run("Successful verification", func(t *testing.T) {
		userID := uuid.New()
		passwordHash, _ := auth.HashPassword("password123")
		user := &auth.User{
			ID:            userID,
			Username:      "testuser",
			Email:         "test@example.com",
			PasswordHash:  passwordHash,
			Role:          auth.RoleAdmin,
			LoginAttempts: 0,
		}

		mockTracker.On("GetByIdentifier", ctx, "test@example.com").Return(user, nil).Once()
		mockTracker.On("TrackSucccessfulLogin", ctx, user).Return(nil).Once()

		identity, err := provider.VerifyIdentity(ctx, "test@example.com", "password123")

		assert.NoError(t, err)
		assert.NotNil(t, identity)
		assert.Equal(t, userID.String(), identity.ID())
		assert.Equal(t, "testuser", identity.Username())
		assert.Equal(t, "test@example.com", identity.Email())
		assert.Equal(t, auth.RoleAdmin, identity.Role())

		mockTracker.AssertExpectations(t)
	})

	t.Run("Invalid password", func(t *testing.T) {
		userID := uuid.New()
		passwordHash, _ := auth.HashPassword("correct_password")
		user := &auth.User{
			ID:            userID,
			Username:      "testuser",
			Email:         "test@example.com",
			PasswordHash:  passwordHash,
			Role:          auth.RoleAdmin,
			LoginAttempts: 0,
		}

		mockTracker.On("GetByIdentifier", ctx, "test@example.com").Return(user, nil).Once()
		mockTracker.On("TrackAttemptedLogin", ctx, user).Return(nil).Once()

		identity, err := provider.VerifyIdentity(ctx, "test@example.com", "wrong_password")

		assert.Error(t, err)
		assert.Nil(t, identity)
		assert.Contains(t, err.Error(), "identity auth")

		mockTracker.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockTracker.On("GetByIdentifier", ctx, "nonexistent@example.com").
			Return(nil, errors.New("user not found")).Once()

		identity, err := provider.VerifyIdentity(ctx, "nonexistent@example.com", "password123")

		assert.Error(t, err)
		assert.Nil(t, identity)
		assert.Contains(t, err.Error(), "find identity")

		mockTracker.AssertExpectations(t)
	})

	t.Run("Too many login attempts", func(t *testing.T) {
		userID := uuid.New()
		passwordHash, _ := auth.HashPassword("password123")
		now := time.Now()
		user := &auth.User{
			ID:             userID,
			Username:       "testuser",
			Email:          "test@example.com",
			PasswordHash:   passwordHash,
			Role:           auth.RoleAdmin,
			LoginAttempts:  auth.MaxLoginAttempts + 1,
			LoginAttemptAt: &now,
		}

		mockTracker.On("GetByIdentifier", ctx, "test@example.com").Return(user, nil).Once()

		identity, err := provider.VerifyIdentity(ctx, "test@example.com", "password123")

		assert.Error(t, err)
		assert.Nil(t, identity)
		assert.Equal(t, auth.ErrTooManyLoginAttempts, err)

		mockTracker.AssertExpectations(t)
	})

	t.Run("Login attempts cooldown expired", func(t *testing.T) {
		userID := uuid.New()
		passwordHash, _ := auth.HashPassword("password123")
		oldAttempt := time.Now().Add(-48 * time.Hour)
		user := &auth.User{
			ID:             userID,
			Username:       "testuser",
			Email:          "test@example.com",
			PasswordHash:   passwordHash,
			Role:           auth.RoleAdmin,
			LoginAttempts:  auth.MaxLoginAttempts + 1,
			LoginAttemptAt: &oldAttempt,
		}

		mockTracker.On("GetByIdentifier", ctx, "test@example.com").Return(user, nil).Once()
		mockTracker.On("TrackSucccessfulLogin", ctx, mock.MatchedBy(func(u *auth.User) bool {
			return u.ID == userID && u.LoginAttempts == 0 // attempts reset
		})).Return(nil).Once()

		identity, err := provider.VerifyIdentity(ctx, "test@example.com", "password123")

		assert.NoError(t, err)
		assert.NotNil(t, identity)
		assert.Equal(t, userID.String(), identity.ID())

		mockTracker.AssertExpectations(t)
	})
}

func TestUserProviderFindIdentityByIdentifier(t *testing.T) {
	ctx := context.Background()
	mockTracker := new(MockUserTracker)

	provider := auth.NewUserProvider(mockTracker)

	t.Run("User found", func(t *testing.T) {
		userID := uuid.New()
		user := &auth.User{
			ID:       userID,
			Username: "testuser",
			Email:    "test@example.com",
			Role:     auth.RoleAdmin,
		}

		mockTracker.On("GetByIdentifier", ctx, "test@example.com").Return(user, nil).Once()

		identity, err := provider.FindIdentityByIdentifier(ctx, "test@example.com")

		assert.NoError(t, err)
		assert.NotNil(t, identity)
		assert.Equal(t, userID.String(), identity.ID())
		assert.Equal(t, "testuser", identity.Username())
		assert.Equal(t, "test@example.com", identity.Email())
		assert.Equal(t, auth.RoleAdmin, identity.Role())

		mockTracker.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		mockTracker.On("GetByIdentifier", ctx, "nonexistent@example.com").
			Return(nil, errors.New("user not found")).Once()

		identity, err := provider.FindIdentityByIdentifier(ctx, "nonexistent@example.com")

		assert.Error(t, err)
		assert.Nil(t, identity)
		assert.Contains(t, err.Error(), "unable to find user")

		mockTracker.AssertExpectations(t)
	})

	t.Run("Invalid role", func(t *testing.T) {
		userID := uuid.New()
		user := &auth.User{
			ID:       userID,
			Username: "testuser",
			Email:    "test@example.com",
			Role:     "invalid_role",
		}

		mockTracker.On("GetByIdentifier", ctx, "test@example.com").Return(user, nil).Once()

		identity, err := provider.FindIdentityByIdentifier(ctx, "test@example.com")

		assert.Error(t, err)
		assert.Nil(t, identity)
		assert.Contains(t, err.Error(), "unknown role")

		mockTracker.AssertExpectations(t)
	})
}

func TestUserProviderValidation(t *testing.T) {
	mockTracker := new(MockUserTracker)

	provider := auth.NewUserProvider(mockTracker)

	validRoles := []string{
		auth.RoleAdmin,
		auth.RoleCustomer,
		auth.RoleEditor,
		auth.RoleGuest,
		auth.RoleViewer,
	}

	for _, role := range validRoles {
		t.Run("Valid role: "+role, func(t *testing.T) {
			user := &auth.User{
				ID:       uuid.New(),
				Username: "testuser",
				Email:    "test@example.com",
				Role:     role,
			}

			err := provider.Validator(user)
			assert.NoError(t, err)
		})
	}

	t.Run("Invalid role", func(t *testing.T) {
		user := &auth.User{
			ID:       uuid.New(),
			Username: "testuser",
			Email:    "test@example.com",
			Role:     "invalid_role",
		}

		err := provider.Validator(user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown role")
	})

	t.Run("Custom validator", func(t *testing.T) {
		customErr := errors.New("custom validation error")
		provider.Validator = func(u *auth.User) error {
			return customErr
		}

		user := &auth.User{
			ID:       uuid.New(),
			Username: "testuser",
			Email:    "test@example.com",
		}

		err := provider.Validator(user)
		assert.Error(t, err)
		assert.Equal(t, customErr, err)
	})
}
