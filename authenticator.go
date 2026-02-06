package auth

import (
	"context"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	tokenValidator  TokenValidator
	activitySink    ActivitySink
	claimsDecorator ClaimsDecorator
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
		activitySink:    noopActivitySink{},
		claimsDecorator: noopClaimsDecorator{},
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

// WithActivitySink configures an ActivitySink for emitting auth events.
func (s *Auther) WithActivitySink(sink ActivitySink) *Auther {
	s.activitySink = normalizeActivitySink(sink)
	return s
}

// WithClaimsDecorator configures a ClaimsDecorator for enriching JWTs.
func (s *Auther) WithClaimsDecorator(decorator ClaimsDecorator) *Auther {
	s.claimsDecorator = normalizeClaimsDecorator(decorator)
	return s
}

// WithTokenValidator sets a custom token validator for externally issued tokens.
func (s *Auther) WithTokenValidator(validator TokenValidator) *Auther {
	s.tokenValidator = validator
	return s
}

// TokenService returns the TokenService instance used by this Authenticator
func (s *Auther) TokenService() TokenService {
	return s.tokenService
}

func (s *Auther) Login(ctx context.Context, identifier, password string) (string, error) {
	var err error
	var identity Identity

	if identity, err = s.provider.VerifyIdentity(ctx, identifier, password); err != nil {
		s.logger.Error("Login verify identity error", "error", err)
		s.emitAuthEvent(ctx, ActivityEventLoginFailure, ActorRef{Type: "unknown"}, "", map[string]any{
			"identifier": identifier,
			"error":      err.Error(),
		})
		return "", err
	}

	if identity == nil || reflect.ValueOf(identity).IsZero() {
		s.logger.Error("Login identity is nil or zero value")
		s.emitAuthEvent(ctx, ActivityEventLoginFailure, ActorRef{Type: "unknown"}, "", map[string]any{
			"identifier": identifier,
			"error":      ErrIdentityNotFound.Error(),
		})
		return "", ErrIdentityNotFound
	}

	if status, err := s.ensureIdentityActive(identity); err != nil {
		s.logger.Warn("Login blocked due to user status", "status", status, "error", err)
		s.emitAuthEvent(ctx, ActivityEventLoginFailure, s.actorFromIdentity(identity), identity.ID(), map[string]any{
			"identifier": identifier,
			"error":      err.Error(),
			"status":     status,
		})
		return "", err
	}

	// Fetch resource roles and generate structured token
	resourceRoles, err := s.roleProvider.FindResourceRoles(ctx, identity)
	if err != nil {
		s.logger.Error("Login failed to fetch resource roles", "error", err)
		s.emitAuthEvent(ctx, ActivityEventLoginFailure, s.actorFromIdentity(identity), identity.ID(), map[string]any{
			"identifier": identifier,
			"error":      err.Error(),
		})
		return "", err
	}

	token, err := s.generateJWT(ctx, identity, resourceRoles)
	if err != nil {
		s.emitAuthEvent(ctx, ActivityEventLoginFailure, s.actorFromIdentity(identity), identity.ID(), map[string]any{
			"identifier": identifier,
			"error":      err.Error(),
		})
		return "", err
	}

	s.emitAuthEvent(ctx, ActivityEventLoginSuccess, s.actorFromIdentity(identity), identity.ID(), map[string]any{
		"identifier": identifier,
	})

	return token, nil
}

func (s *Auther) Impersonate(ctx context.Context, identifier string) (string, error) {
	var err error
	var identity Identity

	if identity, err = s.provider.FindIdentityByIdentifier(ctx, identifier); err != nil {
		s.logger.Error("Impersonate verify identity error", "error", err)
		s.emitAuthEvent(ctx, ActivityEventImpersonationFailure, ActorRef{Type: "system"}, "", map[string]any{
			"identifier": identifier,
			"error":      err.Error(),
		})
		return "", err
	}

	if identity == nil || reflect.ValueOf(identity).IsZero() {
		s.logger.Error("Impersonate identity is nil")
		s.emitAuthEvent(ctx, ActivityEventImpersonationFailure, ActorRef{Type: "system"}, "", map[string]any{
			"identifier": identifier,
			"error":      ErrIdentityNotFound.Error(),
		})
		return "", ErrIdentityNotFound
	}

	if status, err := s.ensureIdentityActive(identity); err != nil {
		s.logger.Warn("Impersonation blocked due to user status", "status", status, "error", err)
		s.emitAuthEvent(ctx, ActivityEventImpersonationFailure, ActorRef{Type: "system"}, identity.ID(), map[string]any{
			"identifier": identifier,
			"error":      err.Error(),
			"status":     status,
		})
		return "", err
	}

	// Fetch resource roles and generate structured token
	resourceRoles, err := s.roleProvider.FindResourceRoles(ctx, identity)
	if err != nil {
		s.logger.Error("Impersonate failed to fetch resource roles", "error", err)
		s.emitAuthEvent(ctx, ActivityEventImpersonationFailure, ActorRef{Type: "system"}, identity.ID(), map[string]any{
			"identifier": identifier,
			"error":      err.Error(),
		})
		return "", err
	}

	token, err := s.generateJWT(ctx, identity, resourceRoles)
	if err != nil {
		s.emitAuthEvent(ctx, ActivityEventImpersonationFailure, ActorRef{Type: "system"}, identity.ID(), map[string]any{
			"identifier": identifier,
			"error":      err.Error(),
		})
		return "", err
	}

	s.emitAuthEvent(ctx, ActivityEventImpersonationSuccess, ActorRef{Type: "system"}, identity.ID(), map[string]any{
		"identifier": identifier,
	})

	return token, nil
}

func (s *Auther) IdentityFromSession(ctx context.Context, session Session) (Identity, error) {
	identity, err := s.provider.FindIdentityByIdentifier(ctx, session.GetUserID())

	if err != nil {
		s.logger.Error("IdentityFromSession findidentity by identifier: %s", err)
		return nil, err
	}

	return identity, nil
}

func (s Auther) SessionFromToken(raw string) (Session, error) {
	validator := s.tokenValidator
	if validator == nil {
		validator = s.tokenService
	}

	claims, err := validator.Validate(raw)
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
func (s *Auther) generateJWT(ctx context.Context, identity Identity, resourceRoles map[string]string) (string, error) {
	claims := s.newJWTClaims(identity, resourceRoles)
	snapshot := captureImmutableClaims(claims)

	decorator := normalizeClaimsDecorator(s.claimsDecorator)
	if err := decorator.Decorate(ctx, identity, claims); err != nil {
		s.logger.Error("claims decorator failed", "error", err)
		return "", err
	}

	if err := snapshot.validate(claims); err != nil {
		s.logger.Error("claims decorator mutated immutable claims", "error", err)
		return "", err
	}

	return s.tokenService.SignClaims(claims)
}

func (s *Auther) newJWTClaims(identity Identity, resourceRoles map[string]string) *JWTClaims {
	now := time.Now()

	var aud jwt.ClaimStrings
	if len(s.audience) > 0 {
		aud = make(jwt.ClaimStrings, len(s.audience))
		copy(aud, s.audience)
	}

	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   identity.ID(),
			Audience:  aud,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(s.tokenExpiration) * time.Hour)),
		},
		UID:       identity.ID(),
		UserRole:  identity.Role(),
		Resources: resourceRoles,
	}

	ensureTokenID(&claims.RegisteredClaims)

	return claims
}

func (s *Auther) emitAuthEvent(ctx context.Context, eventType ActivityEventType, actor ActorRef, userID string, metadata map[string]any) {
	sink := normalizeActivitySink(s.activitySink)
	event := ActivityEvent{
		EventType: eventType,
		Actor:     actor,
		UserID:    userID,
		Metadata:  metadata,
	}

	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}

	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now()
	}

	if err := sink.Record(ctx, event); err != nil {
		s.logger.Warn("activity sink record error: %v", err)
	}
}

func (s *Auther) actorFromIdentity(identity Identity) ActorRef {
	if identity == nil {
		return ActorRef{Type: "unknown"}
	}

	return ActorRef{
		ID:   identity.ID(),
		Type: "user",
	}
}

func (s *Auther) ensureIdentityActive(identity Identity) (UserStatus, error) {
	status, ok := identityStatus(identity)
	if !ok {
		return "", nil
	}

	if status == "" {
		status = UserStatusActive
	}

	if err := statusAuthError(status); err != nil {
		return status, err
	}

	return status, nil
}

type statusAwareIdentity interface {
	Status() UserStatus
}

func identityStatus(identity Identity) (UserStatus, bool) {
	if identity == nil {
		return "", false
	}

	if sa, ok := identity.(statusAwareIdentity); ok {
		return sa.Status(), true
	}

	return "", false
}
