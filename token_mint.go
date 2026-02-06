package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	goerrors "github.com/goliatone/go-errors"
)

// ScopedTokenOptions controls how MintScopedToken issues short-lived tokens.
type ScopedTokenOptions struct {
	// TTL overrides the default token expiration. Zero uses TokenService defaults.
	TTL time.Duration
	// Issuer overrides the default issuer if provided.
	Issuer string
	// Audience overrides the default audience if provided.
	Audience []string
	// IssuedAt overrides the issuance time. Zero uses time.Now().
	IssuedAt time.Time
	// Scopes sets the optional scopes claim on the minted token.
	Scopes []string
}

type tokenDefaults struct {
	issuer   string
	audience jwt.ClaimStrings
	ttl      time.Duration
}

type tokenDefaultsProvider interface {
	tokenDefaults() tokenDefaults
}

// MintScopedToken mints a short-lived JWT with optional scopes and TTL override.
// It uses TokenService defaults for issuer, audience, and TTL when available.
func MintScopedToken(tokenService TokenService, identity Identity, resourceRoles map[string]string, opts ScopedTokenOptions) (string, time.Time, error) {
	if tokenService == nil {
		return "", time.Time{}, goerrors.New("token service is required", goerrors.CategoryBadInput)
	}
	if identity == nil {
		return "", time.Time{}, goerrors.New("identity is required", goerrors.CategoryBadInput)
	}

	issuer := opts.Issuer
	audience := opts.Audience
	ttl := opts.TTL

	if defaultsProvider, ok := tokenService.(tokenDefaultsProvider); ok {
		defaults := defaultsProvider.tokenDefaults()
		if issuer == "" {
			issuer = defaults.issuer
		}
		if len(audience) == 0 {
			audience = defaults.audience
		}
		if ttl == 0 {
			ttl = defaults.ttl
		}
	}

	if ttl < 0 {
		return "", time.Time{}, goerrors.New("token TTL must be non-negative", goerrors.CategoryBadInput)
	}

	issuedAt := opts.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}

	expiresAt := issuedAt.Add(ttl)

	var aud jwt.ClaimStrings
	if len(audience) > 0 {
		aud = make(jwt.ClaimStrings, len(audience))
		copy(aud, audience)
	}

	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   identity.ID(),
			Audience:  aud,
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		UID:       identity.ID(),
		UserRole:  identity.Role(),
		Resources: resourceRoles,
	}

	if len(opts.Scopes) > 0 {
		claims.Scopes = append([]string(nil), opts.Scopes...)
	}

	ensureTokenID(&claims.RegisteredClaims)

	token, err := tokenService.SignClaims(claims)
	if err != nil {
		return "", time.Time{}, err
	}

	return token, expiresAt, nil
}
