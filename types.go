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
	Warn(format string, args ...any)
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

// RoleCapableSession extends Session with role-based access control capabilities
type RoleCapableSession interface {
	Session // Embed the existing Session interface

	// CanRead checks if the role can read a specific resource
	CanRead(resource string) bool

	// CanEdit checks if the role can edit a specific resource
	CanEdit(resource string) bool

	// CanCreate checks if the role can create a specific resource
	CanCreate(resource string) bool

	// CanDelete checks if the role can delete a specific resource
	CanDelete(resource string) bool

	// HasRole checks if the user has a specific role
	HasRole(role string) bool

	// IsAtLeast checks if the user's role is at least the minimum required role
	IsAtLeast(minRole UserRole) bool
}

// TokenService provides transport-agnostic JWT operations
type TokenService interface {
	// Generate creates a new JWT token for the given identity with resource-specific roles
	Generate(identity Identity, resourceRoles map[string]string) (string, error)

	// SignClaims signs the provided claims without mutating registered fields, enabling
	// callers to apply decorators before the token is finalized.
	SignClaims(claims *JWTClaims) (string, error)

	// Validate parses and validates a token string, returning structured claims
	Validate(tokenString string) (AuthClaims, error)
}

// Authenticator holds methods to deal with authentication
type Authenticator interface {
	Login(ctx context.Context, identifier, password string) (string, error)
	Impersonate(ctx context.Context, identifier string) (string, error)
	SessionFromToken(token string) (Session, error)
	IdentityFromSession(ctx context.Context, session Session) (Identity, error)
	TokenService() TokenService
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

// ResourceRoleProvider is an optional interface for fetching resource-specific roles.
// If provided to an Auther, it will be used to embed fine-grained permissions
// into the JWT, upgrading it to a structured claims format.
type ResourceRoleProvider interface {
	FindResourceRoles(ctx context.Context, identity Identity) (map[string]string, error)
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

func (d defLogger) Warn(format string, args ...any) {
	fmt.Printf("[WRN] AUTH "+newline(format), args...)
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
