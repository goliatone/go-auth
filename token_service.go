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

// Generate creates a new JWT token for the given identity using structured claims
func (ts *TokenServiceImpl) Generate(identity Identity) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   identity.ID(),
			Audience:  ts.audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ts.tokenExpiration) * time.Hour)),
		},
		UID:      identity.ID(),
		UserRole: identity.Role(),
		// Resources will be empty for simple generation, enhanced generation handled separately
		Resources: make(map[string]string),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedString, err := token.SignedString(ts.signingKey)
	if err != nil {
		return "", errors.Wrap(err, errors.CategoryInternal, "failed to sign JWT")
	}

	return signedString, nil
}

// GenerateWithResources creates a JWT token with resource-specific roles
func (ts *TokenServiceImpl) GenerateWithResources(identity Identity, resourceRoles map[string]string) (string, error) {
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
		return "", errors.Wrap(err, errors.CategoryInternal, "failed to sign enhanced JWT")
	}

	return signedString, nil
}

// Validate parses and validates a token string, returning structured claims
// Handles both new JWTClaims format and legacy jwt.MapClaims format for backward compatibility
func (ts *TokenServiceImpl) Validate(tokenString string) (AuthClaims, error) {
	// First, try to parse as new structured claims
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			ts.logger.Error("TokenService validate encountered unexpected signing method", "alg", t.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return ts.signingKey, nil
	})

	if err == nil && token.Valid {
		if claims, ok := token.Claims.(*JWTClaims); ok {
			return claims, nil
		}
	}

	// If structured parsing failed, try legacy MapClaims format for backward compatibility
	token, err = jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
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

	if claims, ok := token.Claims.(*jwt.MapClaims); ok && token.Valid {
		// Convert legacy MapClaims to structured AuthClaims
		return ts.mapClaimsToAuthClaims(*claims)
	}

	ts.logger.Error("TokenService validate could not decode or validate claims")
	return nil, ErrUnableToDecodeSession
}

// mapClaimsToAuthClaims converts legacy jwt.MapClaims to AuthClaims for backward compatibility
func (ts *TokenServiceImpl) mapClaimsToAuthClaims(claims jwt.MapClaims) (AuthClaims, error) {
	// Extract standard claims
	sub, err := claims.GetSubject()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	iss, err := claims.GetIssuer()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	eat, err := claims.GetExpirationTime()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	iat, err := claims.GetIssuedAt()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	// Extract role from legacy "dat" field
	role := ""
	resources := make(map[string]string)

	if datValue, exists := claims["dat"]; exists {
		if dat, ok := datValue.(map[string]any); ok {
			if roleValue, exists := dat["role"]; exists {
				if roleStr, ok := roleValue.(string); ok {
					role = roleStr
				}
			}
			// Check if resources exist in legacy format
			if resourcesValue, exists := dat["resources"]; exists {
				if resourcesMap, ok := resourcesValue.(map[string]any); ok {
					for resource, roleValue := range resourcesMap {
						if roleStr, ok := roleValue.(string); ok {
							resources[resource] = roleStr
						}
					}
				}
			}
		}
	}

	// Create structured claims from legacy data
	structuredClaims := &JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			Audience:  aud,
			ExpiresAt: eat,
			IssuedAt:  iat,
		},
		UID:       sub,
		UserRole:  role,
		Resources: resources,
	}

	return structuredClaims, nil
}
