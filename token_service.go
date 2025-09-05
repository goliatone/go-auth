package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-errors"
)

// TokenServiceImpl implements the TokenService interface
type TokenServiceImpl struct {
	signingKey      []byte
	tokenExpiration int
	issuer          string
	audience        jwt.ClaimStrings
	logger          Logger
}

// NewTokenService creates a new TokenService instance
func NewTokenService(signingKey []byte, tokenExpiration int, issuer string, audience jwt.ClaimStrings, logger Logger) TokenService {
	if logger == nil {
		logger = defLogger{}
	}
	return &TokenServiceImpl{
		signingKey:      signingKey,
		tokenExpiration: tokenExpiration,
		issuer:          issuer,
		audience:        audience,
		logger:          logger,
	}
}

// Generate creates a JWT token with resource specific roles
func (ts *TokenServiceImpl) Generate(identity Identity, resourceRoles map[string]string) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   identity.ID(),
			Audience:  ts.audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ts.tokenExpiration) * time.Hour)),
		},
		UID:       identity.ID(),
		UserRole:  identity.Role(),
		Resources: resourceRoles,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedString, err := token.SignedString(ts.signingKey)
	if err != nil {
		return "", errors.Wrap(err, errors.CategoryInternal, "failed to sign JWT")
	}

	return signedString, nil
}

// Validate parses and validates a token string, returning structured claims
func (ts *TokenServiceImpl) Validate(tokenString string) (AuthClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			ts.logger.Error("TokenService validate encountered unexpected signing method", "alg", t.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return ts.signingKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, errors.Wrap(err, ErrTokenMalformed.Category, ErrTokenMalformed.Message).WithTextCode(ErrTokenMalformed.TextCode)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	ts.logger.Error("TokenService validate could not decode or validate claims")
	return nil, ErrUnableToDecodeSession
}
