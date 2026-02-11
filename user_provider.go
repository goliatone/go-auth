package auth

import (
	"context"

	"github.com/goliatone/go-errors"
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
	logger    Logger
	provider  LoggerProvider
}

// MaxLoginAttempts is the maximun number of attempts a user gets
// in a period
var MaxLoginAttempts = 5

// CoolDownPeriod is the period in which we enforce a cool down
var CoolDownPeriod = "24h"

// NewUserProvider will create a new UserProvider
func NewUserProvider(store UserTracker) *UserProvider {
	loggerProvider, logger := ResolveLogger("auth.user_provider", nil, nil)
	return &UserProvider{
		store:     store,
		logger:    logger,
		provider:  loggerProvider,
		Validator: defaultValidator,
	}
}

func (u *UserProvider) WithLogger(l Logger) *UserProvider {
	u.provider, u.logger = ResolveLogger("auth.user_provider", u.provider, l)
	return u
}

// WithLoggerProvider overrides the logger provider used by the user provider.
func (u *UserProvider) WithLoggerProvider(provider LoggerProvider) *UserProvider {
	u.provider, u.logger = ResolveLogger("auth.user_provider", provider, u.logger)
	return u
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
		if errors.IsNotFound(err) {
			return nil, ErrMismatchedHashAndPassword
		}
		return nil, errors.Wrap(err, errors.CategoryInternal, "failed to retrieve user during verification")
	}

	if err := ensureAuthenticatableUser(user); err != nil {
		return nil, err
	}

	if user.LoginAttemptAt != nil {
		expired, err := IsOutsideThresholdPeriod(*user.LoginAttemptAt, CoolDownPeriod)
		if err != nil {
			return nil, errors.Wrap(err, errors.CategoryInternal, "failed to calculdate login attempt cooldown")
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
			return nil, errors.Wrap(err2, errors.CategoryInternal, "failed to track login attempt")
		}

		return nil, ErrMismatchedHashAndPassword
	}

	// reset the login_attempts counter and login_attempt_at
	if err := u.store.TrackSucccessfulLogin(ctx, user); err != nil {
		u.logger.Error("failed to track successful login", "error", err)
	}

	if err := u.validate(user); err != nil {
		return nil, err
	}

	aid := authIdentity{
		id:       user.ID.String(), // user.GetID(),
		email:    user.Email,
		username: user.Username,
		role:     string(user.Role),
		status:   user.Status,
	}

	return aid, nil
}

func (u UserProvider) FindIdentityByIdentifier(ctx context.Context, identfier string) (Identity, error) {
	user, err := u.store.GetByIdentifier(ctx, identfier)
	if err != nil {
		return nil, err
	}

	if err := ensureAuthenticatableUser(user); err != nil {
		return nil, err
	}

	if err := u.validate(user); err != nil {
		return nil, err
	}

	aid := authIdentity{
		email:    user.Email,
		id:       user.ID.String(),
		username: user.Username,
		role:     string(user.Role),
		status:   user.Status,
	}

	return aid, nil

}

type authIdentity struct {
	id       string
	username string
	email    string
	role     string
	status   UserStatus
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

func (a authIdentity) Status() UserStatus {
	if a.status == "" {
		return UserStatusActive
	}
	return a.status
}

var _ Identity = authIdentity{}

func defaultValidator(u *User) error {
	switch u.Role {
	case RoleOwner, RoleAdmin, RoleMember, RoleGuest:
		return nil
	default:
		return errors.New("user has an unkonwn or invalid role", errors.CategoryAuth).
			WithTextCode("INVALID_ROLE").
			WithMetadata(map[string]any{"role": u.Role, "user_id": u.ID.String()})
	}
}

func ensureAuthenticatableUser(user *User) error {
	if user == nil {
		return ErrIdentityNotFound
	}

	user.EnsureStatus()
	if err := statusAuthError(user.Status); err != nil {
		return err
	}

	return nil
}
