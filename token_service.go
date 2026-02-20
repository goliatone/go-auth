package auth

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
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

	legacyFatClaims    bool
	metadataStripKeys  map[string]struct{}
	warnThresholdBytes int
	hardLimitBytes     int

	signedCount        atomic.Uint64
	sizeWarningCount   atomic.Uint64
	sizeRejectionCount atomic.Uint64
}

// TokenServiceStats exposes runtime counters for token signing operations.
type TokenServiceStats struct {
	SignedTokens   uint64
	SizeWarnings   uint64
	SizeRejections uint64
}

// NewTokenService creates a new TokenService instance.
func NewTokenService(signingKey []byte, tokenExpiration int, issuer string, audience jwt.ClaimStrings, logger Logger, opts ...TokenServiceOption) TokenService {
	logger = EnsureLogger(logger)
	service := &TokenServiceImpl{
		signingKey:         signingKey,
		tokenExpiration:    tokenExpiration,
		issuer:             issuer,
		audience:           audience,
		logger:             logger,
		legacyFatClaims:    false,
		metadataStripKeys:  makeClaimsMetadataStripSet(defaultFatClaimsMetadataKeys),
		warnThresholdBytes: DefaultTokenWarnThresholdBytes,
		hardLimitBytes:     DefaultTokenHardLimitBytes,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(service)
	}
	return service
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

	ensureTokenID(&claims.RegisteredClaims)

	return ts.SignClaimsWithType(claims, TokenTypeSession)
}

// SignClaims signs arbitrary JWT claims using the configured signing key.
func (ts *TokenServiceImpl) SignClaims(claims *JWTClaims) (string, error) {
	return ts.signClaims(claims, TokenTypeCustom)
}

// SignClaimsWithType signs claims and annotates guardrail logs/errors with the
// provided token type.
func (ts *TokenServiceImpl) SignClaimsWithType(claims *JWTClaims, tokenType string) (string, error) {
	return ts.signClaims(claims, tokenType)
}

func (ts *TokenServiceImpl) signClaims(claims *JWTClaims, tokenType string) (string, error) {
	if claims == nil {
		return "", errors.New("claims must not be nil", errors.CategoryInternal)
	}

	if !ts.legacyFatClaims {
		if stripped := stripLargeMetadataClaims(claims.Metadata, ts.metadataStripKeys); len(stripped) > 0 {
			ts.logger.Debug(
				"token claims metadata minimized",
				"removed_keys", stripped,
				"token_type", normalizeTokenType(tokenType),
			)
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedString, err := token.SignedString(ts.signingKey)
	if err != nil {
		return "", errors.Wrap(err, errors.CategoryInternal, "failed to sign JWT")
	}

	tokenType = normalizeTokenType(tokenType)
	sizeBytes := len(signedString)
	if ts.hardLimitBytes > 0 && sizeBytes > ts.hardLimitBytes {
		ts.sizeRejectionCount.Add(1)
		ts.logger.Error(
			"token size exceeds hard limit",
			"token_type", tokenType,
			"size_bytes", sizeBytes,
			"warn_threshold_bytes", ts.warnThresholdBytes,
			"hard_limit_bytes", ts.hardLimitBytes,
		)
		return "", newTokenTooLargeError(sizeBytes, ts.hardLimitBytes, tokenType)
	}

	if ts.warnThresholdBytes > 0 && sizeBytes >= ts.warnThresholdBytes {
		ts.sizeWarningCount.Add(1)
		ts.logger.Warn(
			"token size exceeded warning threshold",
			"token_type", tokenType,
			"size_bytes", sizeBytes,
			"warn_threshold_bytes", ts.warnThresholdBytes,
			"hard_limit_bytes", ts.hardLimitBytes,
		)
	}

	ts.signedCount.Add(1)
	return signedString, nil
}

// Validate parses and validates a token string, returning structured claims
func (ts *TokenServiceImpl) Validate(tokenString string) (AuthClaims, error) {
	parserOptions := make([]jwt.ParserOption, 0, 2)
	if ts.issuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(ts.issuer))
	}
	if len(ts.audience) > 0 {
		parserOptions = append(parserOptions, jwt.WithAudience(ts.audience...))
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			ts.logger.Error("TokenService validate encountered unexpected signing method", "alg", t.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return ts.signingKey, nil
	}, parserOptions...)

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

func (ts *TokenServiceImpl) tokenDefaults() tokenDefaults {
	var aud jwt.ClaimStrings
	if len(ts.audience) > 0 {
		aud = make(jwt.ClaimStrings, len(ts.audience))
		copy(aud, ts.audience)
	}

	return tokenDefaults{
		issuer:   ts.issuer,
		audience: aud,
		ttl:      time.Duration(ts.tokenExpiration) * time.Hour,
	}
}

// Stats returns runtime counters for token signing guardrails.
func (ts *TokenServiceImpl) Stats() TokenServiceStats {
	if ts == nil {
		return TokenServiceStats{}
	}
	return TokenServiceStats{
		SignedTokens:   ts.signedCount.Load(),
		SizeWarnings:   ts.sizeWarningCount.Load(),
		SizeRejections: ts.sizeRejectionCount.Load(),
	}
}

func normalizeTokenType(tokenType string) string {
	tokenType = strings.TrimSpace(strings.ToLower(tokenType))
	if tokenType == "" {
		return TokenTypeCustom
	}
	return tokenType
}

func stripLargeMetadataClaims(metadata map[string]any, stripKeys map[string]struct{}) []string {
	if len(metadata) == 0 || len(stripKeys) == 0 {
		return nil
	}

	removed := make([]string, 0, len(stripKeys))
	for key := range metadata {
		if _, ok := stripKeys[normalizeClaimsMetadataKey(key)]; !ok {
			continue
		}
		delete(metadata, key)
		removed = append(removed, key)
	}
	if len(removed) > 1 {
		sort.Strings(removed)
	}
	return removed
}
