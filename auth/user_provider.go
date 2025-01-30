package auth

import (
	"context"
	"errors"
	"fmt"
)

// AccountRegistrerer is the interface we need to handle new user registrations
type AccountRegistrerer interface {
	RegisterUser(ctx context.Context, email, username, password string) (*User, error)
}

// UserTracker is a store we can use to retrieve users
type UserTracker interface {
	GetByIdentifier(ctx context.Context, identifier string) (*User, error)
	TrackAttemptedLogin(ctx context.Context, user *User) error
	TrackSucccessfulLogin(ctx context.Context, user *User) error
}

// UserProvider handles users
type UserProvider struct {
	store     UserTracker
	Validator func(*User) error
}

// MaxLoginAttempts is the maximun number of attempts a user gets
// in a period
var MaxLoginAttempts = 5

// CoolDownPeriod is the period in which we enforce a cool down
var CoolDownPeriod = "24h"

// ErrTooManyLoginAttempts indicates the user has tried to many times
var ErrTooManyLoginAttempts = errors.New("error too many login attempts")

// NewUserProvider will create a new UserProvider
func NewUserProvider(store UserTracker) *UserProvider {
	return &UserProvider{
		store:     store,
		Validator: defaultValidator,
	}
}

func (u *UserProvider) validate(user *User) error {
	if u.Validator != nil {
		return u.Validator(user)
	}
	return defaultValidator(user)
}

// VerifyIdentity will find the user, compare to the password, and return identity
func (u UserProvider) VerifyIdentity(ctx context.Context, identifier, password string) (Identity, error) {
	// TODO: We should select id, password_hash, login_attempts, loging_attempt_at
	user, err := u.store.GetByIdentifier(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("find identity: %w", err)
	}

	if user.LoginAttemptAt != nil {
		expired, err := IsOutsideThresholdPeriod(*user.LoginAttemptAt, CoolDownPeriod)
		if err != nil {
			return nil, fmt.Errorf("error calculating threshold: %w", err)
		}
		if expired {
			user.LoginAttempts = 0
		}
	}

	//if we have too many attempts in the given window, cool off!
	if user.LoginAttempts > MaxLoginAttempts {
		return nil, ErrTooManyLoginAttempts
	}

	if err := ComparePasswordAndHash(password, user.PasswordHash); err != nil {
		// We have to increment the login_attempts counter and login_attempt_at
		if err2 := u.store.TrackAttemptedLogin(ctx, user); err2 != nil {
			err = fmt.Errorf("unable to track attempted login: %w", err2)
		}
		return nil, fmt.Errorf("identity auth: %w", err)
	}

	// reset the login_attempts counter and login_attempt_at
	if err := u.store.TrackSucccessfulLogin(ctx, user); err != nil {
		return nil, fmt.Errorf("unable to reset login attempts: %w", err)
	}
	aid := authIdentity{
		id:       user.ID.String(), // user.GetID(),
		email:    user.Email,
		username: user.Username,
		role:     user.Role,
	}

	if err := u.validate(user); err != nil {
		return nil, err
	}

	return aid, nil
}

func (u UserProvider) FindIdentityByIdentifier(ctx context.Context, identfier string) (Identity, error) {
	user, err := u.store.GetByIdentifier(ctx, identfier)
	if err != nil {
		return nil, fmt.Errorf("unable to find user %s %w:", identfier, err)
	}

	aid := authIdentity{
		email:    user.Email,
		id:       user.ID.String(),
		username: user.Username,
		role:     user.Role,
	}

	if err := u.validate(user); err != nil {
		return nil, err
	}

	return aid, nil

}

type authIdentity struct {
	id       string
	username string
	email    string
	role     string
}

func (a authIdentity) ID() string {
	return a.id
}

func (a authIdentity) Username() string {
	return a.username
}

func (a authIdentity) Email() string {
	return a.email
}

func (a authIdentity) Role() string {
	return a.role
}

var _ Identity = authIdentity{}

func defaultValidator(u *User) error {
	switch u.Role {
	case RoleAdmin:
	case RoleCustomer:
	case RoleEditor:
	case RoleGuest:
	case RoleViewer:
		return nil
	default:
		return errors.New("unknown role")
	}

	return nil
}
