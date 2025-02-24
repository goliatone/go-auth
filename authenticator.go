package auth

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Auther struct {
	provider        IdentityProvider
	signingKey      []byte
	tokenExpiration int
	issuer          string
	audience        jwt.ClaimStrings
}

// TODO: do not return interfaces, return structs
// NewAuthenticator returns a new authenticator
func NewAuthenticator(provider IdentityProvider, opts Config) Authenticator {
	return &Auther{
		provider:        provider,
		signingKey:      []byte(opts.GetSigningKey()),
		tokenExpiration: opts.GetTokenExpiration(),
		audience:        opts.GetAudience(),
		issuer:          opts.GetIssuer(),
	}
}

func (s Auther) Login(ctx context.Context, identifier, password string) (string, error) {
	var err error
	var identity Identity

	if identity, err = s.provider.VerifyIdentity(ctx, identifier, password); err != nil {
		return "", fmt.Errorf("unauthorized: %w", err)
	}

	if identity == nil {
		return "", fmt.Errorf("unauthorized: %w", ErrIdentityNotFound)
	}

	t := reflect.TypeOf(identity)
	if reflect.ValueOf(identity) == reflect.Zero(t) {
		return "", fmt.Errorf("unauthorized: %w", ErrIdentityNotFound)
	}

	return s.generateJWT(identity)
}

func (s Auther) Impersonate(ctx context.Context, identifier string) (string, error) {
	var err error
	var identity Identity

	if identity, err = s.provider.FindIdentityByIdentifier(ctx, identifier); err != nil {
		return "", fmt.Errorf("unauthorized: %w", err)
	}

	if identity == nil {
		return "", fmt.Errorf("unauthorized: %w", ErrIdentityNotFound)
	}

	t := reflect.TypeOf(identity)
	if reflect.ValueOf(identity) == reflect.Zero(t) {
		return "", fmt.Errorf("unauthorized: %w", ErrIdentityNotFound)
	}

	return s.generateJWT(identity)
}

func (s Auther) IdentityFromSession(ctx context.Context, session Session) (Identity, error) {
	var err error
	var identity Identity

	if identity, err = s.provider.FindIdentityByIdentifier(ctx, session.GetUserID()); err != nil {
		return nil, fmt.Errorf("unauthorized: %w", err)
	}
	return identity, nil
}

func (s Auther) SessionFromToken(raw string) (Session, error) {
	token, err := jwt.ParseWithClaims(raw, &jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.signingKey), nil
	})
	if err != nil {
		return nil, err
	}

	var ok bool
	var claims *jwt.MapClaims

	if claims, ok = token.Claims.(*jwt.MapClaims); !ok || !token.Valid {
		return nil, errors.New("unable to decode session")
	}

	return sessionFromClaims(*claims)
}

func (s Auther) generateJWT(identity Identity) (string, error) {
	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": identity.ID(),
		"aud": s.audience,
		"dat": nil,
		"iat": jwt.NewNumericDate(time.Now()),
		"exp": jwt.NewNumericDate(
			time.Now().Add(time.Duration(s.tokenExpiration) * time.Hour),
		),
	}

	dat := map[string]any{}
	dat["role"] = identity.Role()
	claims["dat"] = dat

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(s.signingKey))
}
