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
	configErr       error

	metadataStripKeys  map[string]struct{}
	warnThresholdBytes int
	hardLimitBytes     int

	signedCount        atomic.Uint64
	sizeWarningCount   atomic.Uint64
	sizeRejectionCount atomic.Uint64
}

const MinimumHMACSigningKeyBytes = 32

// TokenServiceStats exposes runtime counters for token signing operations.
type TokenServiceStats struct {
	SignedTokens   uint64
	SizeWarnings   uint64
	SizeRejections uint64
}

// NewTokenService is the compatibility constructor. Invalid configuration
// produces a fail-closed service whose signing and validation methods return
// the configuration error. New code should use NewValidatedTokenService.
func NewTokenService(signingKey []byte, tokenExpiration int, issuer string, audience jwt.ClaimStrings, logger Logger, opts ...TokenServiceOption) TokenService {
	service := newTokenService(signingKey, tokenExpiration, issuer, audience, logger, opts...)
	service.configErr = validateTokenServiceConfig(service)
	return service
}

// NewValidatedTokenService creates a token service only when all signing and
// registered-claim trust-boundary requirements are configured.
func NewValidatedTokenService(signingKey []byte, tokenExpiration int, issuer string, audience jwt.ClaimStrings, logger Logger, opts ...TokenServiceOption) (*TokenServiceImpl, error) {
	service := newTokenService(signingKey, tokenExpiration, issuer, audience, logger, opts...)
	if err := validateTokenServiceConfig(service); err != nil {
		return nil, err
	}
	return service, nil
}

func newTokenService(signingKey []byte, tokenExpiration int, issuer string, audience jwt.ClaimStrings, logger Logger, opts ...TokenServiceOption) *TokenServiceImpl {
	logger = EnsureLogger(logger)
	service := &TokenServiceImpl{
		signingKey:         append([]byte(nil), signingKey...),
		tokenExpiration:    tokenExpiration,
		issuer:             strings.TrimSpace(issuer),
		audience:           append(jwt.ClaimStrings(nil), audience...),
		logger:             logger,
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

func validateTokenServiceConfig(service *TokenServiceImpl) error {
	if service == nil {
		return errors.New("token service is required", errors.CategoryBadInput)
	}
	if len(service.signingKey) < MinimumHMACSigningKeyBytes {
		return errors.New(
			fmt.Sprintf("JWT HMAC signing key must be at least %d bytes", MinimumHMACSigningKeyBytes),
			errors.CategoryBadInput,
		)
	}
	if service.tokenExpiration <= 0 {
		return errors.New("JWT token expiration must be positive", errors.CategoryBadInput)
	}
	if service.issuer == "" {
		return errors.New("JWT issuer is required", errors.CategoryBadInput)
	}
	if len(service.audience) == 0 {
		return errors.New("JWT audience is required", errors.CategoryBadInput)
	}
	for _, audience := range service.audience {
		if strings.TrimSpace(audience) == "" {
			return errors.New("JWT audience entries must not be empty", errors.CategoryBadInput)
		}
	}
	return nil
}

// Generate creates a JWT token with resource specific roles
func (ts *TokenServiceImpl) Generate(identity Identity, resourceRoles map[string]string) (string, error) {
	if err := ts.configurationError(); err != nil {
		return "", err
	}
	if identity == nil || strings.TrimSpace(identity.ID()) == "" {
		return "", errors.New("identity with a subject is required", errors.CategoryBadInput)
	}
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
	if err := ts.configurationError(); err != nil {
		return "", err
	}
	if claims == nil {
		return "", errors.New("claims must not be nil", errors.CategoryInternal)
	}

	tokenType = normalizeTokenType(tokenType)
	if !validTokenUse(tokenType) {
		return "", errors.New("unsupported JWT token use", errors.CategoryBadInput).
			WithMetadata(map[string]any{"token_use": tokenType})
	}
	claims.Use = tokenType
	ensureTokenID(&claims.RegisteredClaims)
	if err := ts.validateRequiredClaims(claims); err != nil {
		return "", err
	}

	if stripped := stripLargeMetadataClaims(claims.Metadata, ts.metadataStripKeys); len(stripped) > 0 {
		ts.logger.Debug(
			"token claims metadata minimized",
			"removed_keys", stripped,
			"token_type", normalizeTokenType(tokenType),
		)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedString, err := token.SignedString(ts.signingKey)
	if err != nil {
		return "", errors.Wrap(err, errors.CategoryInternal, "failed to sign JWT")
	}

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
	if err := ts.configurationError(); err != nil {
		return nil, err
	}
	parserOptions := make([]jwt.ParserOption, 0, 6)
	parserOptions = append(parserOptions,
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if ts.issuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(ts.issuer))
	}
	if len(ts.audience) > 0 {
		parserOptions = append(parserOptions, jwt.WithAudience(ts.audience...))
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
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
		if err := ts.validateRequiredClaims(claims); err != nil {
			return nil, err
		}
		return claims, nil
	}

	ts.logger.Error("TokenService validate could not decode or validate claims")
	return nil, ErrUnableToDecodeSession
}

// ValidateSession validates a token and additionally requires session use.
func (ts *TokenServiceImpl) ValidateSession(tokenString string) (AuthClaims, error) {
	claims, err := ts.Validate(tokenString)
	if err != nil {
		return nil, err
	}
	if err := RequireTokenUse(claims, TokenTypeSession); err != nil {
		return nil, err
	}
	return claims, nil
}

// RequireTokenUse enforces an explicit token-use boundary. Scoped-token
// consumers should call this with TokenTypeScoped after general validation.
func RequireTokenUse(claims AuthClaims, expected string) error {
	expected = normalizeTokenType(expected)
	tokenUse, ok := claims.(TokenUseClaimer)
	if claims == nil || !ok || tokenUse.TokenUse() != expected {
		return errors.New("JWT token use is not valid for this operation", errors.CategoryAuth).
			WithTextCode(ErrTokenMalformed.TextCode)
	}
	return nil
}

func (ts *TokenServiceImpl) configurationError() error {
	if ts == nil {
		return errors.New("token service is not initialized", errors.CategoryInternal)
	}
	return ts.configErr
}

func (ts *TokenServiceImpl) validateRequiredClaims(claims *JWTClaims) error {
	if claims == nil ||
		strings.TrimSpace(claims.Subject()) == "" ||
		strings.TrimSpace(claims.UID) == "" ||
		claims.UID != claims.Subject() ||
		strings.TrimSpace(claims.Issuer) == "" ||
		len(claims.Audience) == 0 ||
		claims.RegisteredClaims.IssuedAt == nil ||
		claims.ExpiresAt == nil ||
		strings.TrimSpace(claims.ID) == "" ||
		!validTokenUse(claims.Use) {
		return errors.New("JWT is missing required claims", errors.CategoryAuth).
			WithTextCode(ErrTokenMalformed.TextCode)
	}
	return nil
}

func validTokenUse(tokenUse string) bool {
	switch strings.TrimSpace(strings.ToLower(tokenUse)) {
	case TokenTypeSession, TokenTypeScoped, TokenTypeCustom:
		return true
	default:
		return false
	}
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
