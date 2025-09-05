package auth

import (
	"context"
	"reflect"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-errors"
)

type Auther struct {
	provider        IdentityProvider
	signingKey      []byte
	tokenExpiration int
	issuer          string
	audience        jwt.ClaimStrings
	logger          Logger
	tokenService    TokenService
}

// TODO: do not return interfaces, return structs
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
		signingKey:      []byte(opts.GetSigningKey()),
		tokenExpiration: opts.GetTokenExpiration(),
		audience:        opts.GetAudience(),
		issuer:          opts.GetIssuer(),
		logger:          defLogger{},
		tokenService:    tokenService,
	}
}

func (s Auther) WithLogger(logger Logger) Auther {
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

	token, err := s.generateJWT(identity)
	if err != nil {
		return "", err
	}

	return token, nil
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

	token, err := s.generateJWT(identity)
	if err != nil {
		return "", err
	}

	return token, nil
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
	token, err := jwt.ParseWithClaims(raw, &jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			s.logger.Error("SessionFromToken encountered unexpected signing method", "alg", t.Header["alg"])
			return nil, errors.New("unexpected signing method")
		}
		return s.signingKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}

		return nil, errors.Wrap(err, ErrTokenMalformed.Category, ErrTokenMalformed.Message).WithTextCode(ErrTokenMalformed.TextCode)
	}

	if claims, ok := token.Claims.(*jwt.MapClaims); ok && token.Valid {
		session, err := sessionFromClaims(*claims)
		if err != nil {
			return nil, err
		}
		return session, nil
	}

	s.logger.Error("SessionFromToken could not decode or validate claims")
	return nil, ErrUnableToDecodeSession
}

func (s Auther) generateJWT(identity Identity) (string, error) {
	// Delegate to TokenService for token generation
	return s.tokenService.Generate(identity)
}

// GenerateEnhancedJWT generates a JWT token using structured claims
// This method creates tokens with enhanced permission capabilities
func (s Auther) GenerateEnhancedJWT(identity Identity, resourceRoles map[string]string) (string, error) {
	// Delegate to TokenService for enhanced token generation
	if tokenServiceImpl, ok := s.tokenService.(*TokenServiceImpl); ok {
		return tokenServiceImpl.GenerateWithResources(identity, resourceRoles)
	}
	// Fallback if TokenService doesn't have GenerateWithResources method
	return s.tokenService.Generate(identity)
}
