package auth0example

import (
	"context"

	auth "github.com/goliatone/go-auth"
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

func (u userTracker) TrackSucccessfulLogin(ctx context.Context, user *auth.User) error {
	return u.users.TrackSucccessfulLogin(ctx, user)
}
