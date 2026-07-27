package extensions

import (
	"context"

	auth "github.com/goliatone/go-auth"
	"github.com/google/uuid"
)

type userTracker struct {
	users auth.Users
}

func (u userTracker) GetByIdentifier(ctx context.Context, identifier string) (*auth.User, error) {
	return u.users.GetByIdentifier(ctx, identifier)
}

func (u userTracker) TrackAttemptedLogin(ctx context.Context, user *auth.User) error {
	return u.users.TrackAttemptedLogin(ctx, user)
}

func (u userTracker) ReserveLoginAttempt(ctx context.Context, userID uuid.UUID, policy auth.LoginAttemptPolicy) (auth.LoginAttemptReservation, error) {
	return u.users.(auth.AtomicLoginAttemptTracker).ReserveLoginAttempt(ctx, userID, policy)
}

func (u userTracker) TrackSucccessfulLogin(ctx context.Context, user *auth.User) error {
	return u.users.TrackSucccessfulLogin(ctx, user)
}
