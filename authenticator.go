package auth

import (
	"context"
	"reflect"
)

type Auther struct {
	provider        IdentityProvider
	roleProvider    ResourceRoleProvider // Mandatory provider for resource-level permissions
	signingKey      []byte
	tokenExpiration int
	issuer          string
	audience        []string
	logger          Logger
	tokenService    TokenService
}

// NewAuthenticator returns a new Authenticator
func NewAuthenticator(provider IdentityProvider, opts Config) *Auther {
	// Initialize TokenService with configuration from opts
	tokenService := NewTokenService(
		[]byte(opts.GetSigningKey()),
		opts.GetTokenExpiration(),
		opts.GetIssuer(),
		opts.GetAudience(),
		defLogger{},
	)

	return &Auther{
		provider:        provider,
		roleProvider:    &noopResourceRoleProvider{}, // Use no-op provider by default
		signingKey:      []byte(opts.GetSigningKey()),
		tokenExpiration: opts.GetTokenExpiration(),
		audience:        opts.GetAudience(),
		issuer:          opts.GetIssuer(),
		logger:          defLogger{},
		tokenService:    tokenService,
	}
}

func (s *Auther) WithLogger(logger Logger) *Auther {
	s.logger = logger
	// Update the TokenService logger as well
	s.tokenService = NewTokenService(
		s.signingKey,
		s.tokenExpiration,
		s.issuer,
		s.audience,
		logger,
	)
	return s
}

// WithResourceRoleProvider sets a custom ResourceRoleProvider for the Auther.
// This enables resource-level permissions in JWT tokens.
func (s *Auther) WithResourceRoleProvider(provider ResourceRoleProvider) *Auther {
	s.roleProvider = provider
	return s
}

// TokenService returns the TokenService instance used by this Authenticator
func (s *Auther) TokenService() TokenService {
	return s.tokenService
}

func (s Auther) Login(ctx context.Context, identifier, password string) (string, error) {
	var err error
	var identity Identity

	if identity, err = s.provider.VerifyIdentity(ctx, identifier, password); err != nil {
		s.logger.Error("Login verify identity error", "error", err)
		return "", err
	}

	if identity == nil || reflect.ValueOf(identity).IsZero() {
		s.logger.Error("Login identity is nil or zero value")
		return "", ErrIdentityNotFound
	}

	// Fetch resource roles and generate structured token
	resourceRoles, err := s.roleProvider.FindResourceRoles(ctx, identity)
	if err != nil {
		s.logger.Error("Login failed to fetch resource roles", "error", err)
		return "", err
	}

	return s.generateJWT(identity, resourceRoles)
}

func (s Auther) Impersonate(ctx context.Context, identifier string) (string, error) {
	var err error
	var identity Identity

	if identity, err = s.provider.FindIdentityByIdentifier(ctx, identifier); err != nil {
		s.logger.Error("Impersonate verify identity error", "error", err)
		return "", err
	}

	if identity == nil || reflect.ValueOf(identity).IsZero() {
		s.logger.Error("Impersonate identity is nil")
		return "", ErrIdentityNotFound
	}

	// Fetch resource roles and generate structured token
	resourceRoles, err := s.roleProvider.FindResourceRoles(ctx, identity)
	if err != nil {
		s.logger.Error("Impersonate failed to fetch resource roles", "error", err)
		return "", err
	}

	return s.generateJWT(identity, resourceRoles)
}

func (s Auther) IdentityFromSession(ctx context.Context, session Session) (Identity, error) {
	identity, err := s.provider.FindIdentityByIdentifier(ctx, session.GetUserID())

	if err != nil {
		s.logger.Error("IdentityFromSession findidentity by identifier: %s", err)
		return nil, err
	}

	return identity, nil
}

func (s Auther) SessionFromToken(raw string) (Session, error) {
	// Use TokenService to validate the token and get AuthClaims
	claims, err := s.tokenService.Validate(raw)
	if err != nil {
		s.logger.Error("SessionFromToken validation failed", "error", err)
		return nil, err
	}

	// Convert AuthClaims to SessionObject
	session, err := sessionFromAuthClaims(claims)
	if err != nil {
		s.logger.Error("SessionFromToken failed to create session from claims", "error", err)
		return nil, err
	}

	return session, nil
}

// generateJWT generates a JWT token using structured claims with resource-specific roles
func (s Auther) generateJWT(identity Identity, resourceRoles map[string]string) (string, error) {
	// Delegate to TokenService for token generation
	return s.tokenService.Generate(identity, resourceRoles)
}
