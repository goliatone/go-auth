package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/goliatone/go-router"
	"github.com/google/uuid"
)

type Logger interface {
	Debug(format string, args ...any)
	Info(format string, args ...any)
	Error(format string, args ...any)
}

// Session holds attributes that are part of an auth session
type Session interface {
	GetUserID() string
	GetUserUUID() (uuid.UUID, error)
	GetAudience() []string
	GetIssuer() string
	GetIssuedAt() *time.Time
	GetData() map[string]any
}

// Authenticator holds methods to deal with authentication
type Authenticator interface {
	Login(ctx context.Context, identifier, password string) (string, error)
	Impersonate(ctx context.Context, identifier string) (string, error)
	SessionFromToken(token string) (Session, error)
	IdentityFromSession(ctx context.Context, session Session) (Identity, error)
}

type LoginPayload interface {
	GetIdentifier() string
	GetPassword() string
	GetExtendedSession() bool
}

type HTTPAuthenticator interface {
	Middleware
	Login(c router.Context, payload LoginPayload) error
	Logout(c router.Context)
	SetRedirect(c router.Context)
	GetRedirect(c router.Context, def ...string) string
	GetRedirectOrDefault(c router.Context) string
	MakeClientRouteAuthErrorHandler(optionalAuth bool) func(c router.Context, err error) error
}

// Identity holds the attributes of an identity
type Identity interface {
	ID() string
	Username() string
	Email() string
	Role() string
}

// Config holds auth options
type Config interface {
	GetSigningKey() string
	GetSigningMethod() string
	GetContextKey() string
	GetTokenExpiration() int
	GetExtendedTokenDuration() int
	GetTokenLookup() string
	GetAuthScheme() string
	GetIssuer() string
	GetAudience() []string
	GetRejectedRouteKey() string
	GetRejectedRouteDefault() string
}

// IdentityProvider ensure we have a store to retrieve auth identity
type IdentityProvider interface {
	VerifyIdentity(ctx context.Context, identifier, password string) (Identity, error)
	FindIdentityByIdentifier(ctx context.Context, identifier string) (Identity, error)
}

// PasswordAuthenticator authenticates passwords
type PasswordAuthenticator interface {
	HashPassword(password string) (string, error)
	ComparePasswordAndHash(password, hash string) error
}

type defLogger struct{}

func (d defLogger) Error(format string, args ...any) {
	fmt.Printf("[ERR] AUTH "+newline(format), args...)
}

func (d defLogger) Info(format string, args ...any) {
	fmt.Printf("[INF] AUTH "+newline(format), args...)
}

func (d defLogger) Debug(format string, args ...any) {
	fmt.Printf("[DBG] AUTH "+newline(format), args...)
}

func newline(s string) string {
	if len(s) > 0 && s[len(s)-1] != '\n' {
		s += "\n"
	}
	return s
}
