package auth

import (
	"context"
	"maps"
	"time"

	"github.com/goliatone/go-errors"
	"github.com/google/uuid"
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

type LoginAttemptPolicy struct {
	MaxAttempts int
	Window      time.Duration
}

type LoginAttemptReservation struct {
	Allowed    bool
	Attempts   int
	RecordedAt time.Time
}

// AtomicLoginAttemptTracker reserves password-verification attempts with one
// database operation so parallel requests cannot exceed the configured budget.
type AtomicLoginAttemptTracker interface {
	ReserveLoginAttempt(context.Context, uuid.UUID, LoginAttemptPolicy) (LoginAttemptReservation, error)
}

// UserProvider handles users
type UserProvider struct {
	store     UserTracker
	Validator func(*User) error
	policy    LoginAttemptPolicy
	logger    Logger
	provider  LoggerProvider
}

const (
	DefaultMaxLoginAttempts   = 5
	DefaultLoginAttemptWindow = 24 * time.Hour
)

// MaxLoginAttempts and CoolDownPeriod remain variables for source
// compatibility. NewUserProvider uses immutable defaults; configure an
// instance with WithLoginAttemptPolicy instead.
var (
	MaxLoginAttempts = DefaultMaxLoginAttempts
	CoolDownPeriod   = "24h"
)

var invalidIdentityPasswordHash = func() string {
	hash, err := HashPassword("go-auth-invalid-identity-password")
	if err != nil {
		panic(err)
	}
	return hash
}()

// NewUserProvider will create a new UserProvider
func NewUserProvider(store UserTracker) *UserProvider {
	loggerProvider, logger := ResolveLogger("auth.user_provider", nil, nil)
	return &UserProvider{
		store:     store,
		logger:    logger,
		provider:  loggerProvider,
		Validator: defaultValidator,
		policy: LoginAttemptPolicy{
			MaxAttempts: DefaultMaxLoginAttempts,
			Window:      DefaultLoginAttemptWindow,
		},
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

func (u *UserProvider) WithLoginAttemptPolicy(policy LoginAttemptPolicy) *UserProvider {
	if policy.MaxAttempts > 0 && policy.Window > 0 {
		u.policy = policy
	}
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
			_ = ComparePasswordAndHash(password, invalidIdentityPasswordHash)
			return nil, ErrMismatchedHashAndPassword
		}
		return nil, errors.Wrap(err, errors.CategoryInternal, "failed to retrieve user during verification")
	}

	if authenticatableErr := ensureAuthenticatableUser(user); authenticatableErr != nil {
		return nil, authenticatableErr
	}

	attempts, ok := u.store.(AtomicLoginAttemptTracker)
	if !ok {
		return nil, errors.New("user tracker does not support atomic login attempt reservations", errors.CategoryInternal)
	}
	reservation, err := attempts.ReserveLoginAttempt(ctx, user.ID, u.policy)
	if err != nil {
		return nil, errors.Wrap(err, errors.CategoryInternal, "failed to reserve login attempt")
	}
	if !reservation.Allowed {
		return nil, ErrTooManyLoginAttempts
	}

	if err := ComparePasswordAndHash(password, user.PasswordHash); err != nil {
		return nil, ErrMismatchedHashAndPassword
	}

	if state := TemporaryPasswordStateFromMetadata(user.Metadata); state.Expired(time.Now()) {
		return nil, ErrTemporaryPasswordExpired
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
		metadata: cloneUserMetadata(user.Metadata),
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
		metadata: cloneUserMetadata(user.Metadata),
	}

	return aid, nil

}

type authIdentity struct {
	id       string
	username string
	email    string
	role     string
	status   UserStatus
	metadata map[string]any
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

func (a authIdentity) Metadata() map[string]any {
	return cloneUserMetadata(a.metadata)
}

var _ Identity = authIdentity{}

func cloneUserMetadata(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	maps.Copy(out, src)
	return out
}

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
