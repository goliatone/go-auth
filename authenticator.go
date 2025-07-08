package auth

import (
	"context"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-errors"
)

type Auther struct {
	provider        IdentityProvider
	signingKey      []byte
	tokenExpiration int
	issuer          string
	audience        jwt.ClaimStrings
	Logger          Logger
}

// TODO: do not return interfaces, return structs
// NewAuthenticator returns a new Authenticator
func NewAuthenticator(provider IdentityProvider, opts Config) *Auther {
	return &Auther{
		provider:        provider,
		signingKey:      []byte(opts.GetSigningKey()),
		tokenExpiration: opts.GetTokenExpiration(),
		audience:        opts.GetAudience(),
		issuer:          opts.GetIssuer(),
		Logger:          defLogger{},
	}
}

func (s Auther) WithLogger(logger Logger) Auther {
	s.Logger = logger
	return s
}

func (s Auther) Login(ctx context.Context, identifier, password string) (string, error) {
	var err error
	var identity Identity

	if identity, err = s.provider.VerifyIdentity(ctx, identifier, password); err != nil {
		s.Logger.Error("Login verify identity error", "error", err)
		return "", err
	}

	if identity == nil || reflect.ValueOf(identity).IsZero() {
		s.Logger.Error("Login identity is nil or zero value")
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
		s.Logger.Error("Impersonate verify identity error", "error", err)
		return "", err
	}

	if identity == nil || reflect.ValueOf(identity).IsZero() {
		s.Logger.Error("Impersonate identity is nil")
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
		s.Logger.Error("IdentityFromSession findidentity by identifier: %s", err)
		return nil, err
	}

	return identity, nil
}

func (s Auther) SessionFromToken(raw string) (Session, error) {
	token, err := jwt.ParseWithClaims(raw, &jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			s.Logger.Error("SessionFromToken encountered unexpected signing method", "alg", t.Header["alg"])
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

	s.Logger.Error("SessionFromToken could not decode or validate claims")
	return nil, ErrUnableToDecodeSession
}

func (s Auther) generateJWT(identity Identity) (string, error) {
	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": identity.ID(),
		"aud": s.audience,
		"dat": map[string]any{
			"role": identity.Role(),
		},
		"iat": jwt.NewNumericDate(time.Now()),
		"exp": jwt.NewNumericDate(
			time.Now().Add(time.Duration(s.tokenExpiration) * time.Hour),
		),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedString, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", errors.Wrap(err, errors.CategoryInternal, "failed to sign JWT")
	}

	return signedString, nil
}
