package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
)

type TokenValidator struct {
	provider  ProviderConfig
	metadata  DiscoveryMetadata
	jwks      *jwksCache
	clock     func() time.Time
	algSet    map[string]struct{}
	contextFn func() context.Context
}

type ValidatorOption func(*validatorOptions)

type validatorOptions struct {
	httpClient *http.Client
	clock      func() time.Time
	contextFn  func() context.Context
}

func WithValidatorHTTPClient(client *http.Client) ValidatorOption {
	return func(opts *validatorOptions) {
		if opts != nil && client != nil {
			opts.httpClient = client
		}
	}
}

func WithValidatorClock(clock func() time.Time) ValidatorOption {
	return func(opts *validatorOptions) {
		if opts != nil && clock != nil {
			opts.clock = clock
		}
	}
}

func WithValidatorContext(fn func() context.Context) ValidatorOption {
	return func(opts *validatorOptions) {
		if opts != nil && fn != nil {
			opts.contextFn = fn
		}
	}
}

func NewTokenValidator(ctx context.Context, provider ProviderConfig, metadata DiscoveryMetadata, opts ...ValidatorOption) (*TokenValidator, error) {
	if err := provider.validate(); err != nil {
		return nil, err
	}
	if err := validateTokenValidationEndpoints(provider, metadata); err != nil {
		return nil, err
	}

	options := validatorOptions{httpClient: http.DefaultClient, clock: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.httpClient == nil {
		options.httpClient = http.DefaultClient
	}
	if options.clock == nil {
		options.clock = time.Now
	}

	algSet := allowedAlgorithmSet(provider, metadata)
	delete(algSet, "none")
	if err := rejectUnsupportedConfiguredAlgorithms(provider, algSet); err != nil {
		return nil, err
	}
	for alg := range algSet {
		if !supportedSigningAlgorithm(alg) {
			delete(algSet, alg)
		}
	}
	if len(algSet) == 0 {
		return nil, cloneWithProvider(ErrInvalidConfig, provider.Key, map[string]any{"field": "allowed_algorithms"})
	}

	validator := &TokenValidator{
		provider: provider,
		metadata: metadata,
		jwks: newJWKSCache(
			metadata.JWKSURI,
			provider.CacheTTL,
			provider.JWKSRefreshCooldown,
			options.httpClient,
			provider.Limits,
			provider.RequestTimeout,
			options.clock,
		),
		clock:     options.clock,
		algSet:    algSet,
		contextFn: options.contextFn,
	}

	if _, err := validator.jwks.keysSnapshot(ctx, true); err != nil {
		return nil, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"cause": "invalid JWKS response"})
	}

	return validator, nil
}

func (v *TokenValidator) Validate(tokenString string) (auth.AuthClaims, error) {
	ctx := context.Background()
	if v != nil && v.contextFn != nil {
		ctx = v.contextFn()
	}
	claims, err := v.validateMapClaims(ctx, tokenString, "", v.provider.Audience)
	if err != nil {
		return nil, err
	}
	return mapTokenClaimsToAuth(claims), nil
}

func (v *TokenValidator) ValidateIDToken(ctx context.Context, rawIDToken string, nonce string) (jwt.MapClaims, error) {
	return v.ValidateIDTokenWithAccessToken(ctx, rawIDToken, nonce, "")
}

func (v *TokenValidator) ValidateIDTokenWithAccessToken(ctx context.Context, rawIDToken string, nonce string, rawAccessToken string) (jwt.MapClaims, error) {
	if v == nil {
		return nil, auth.ErrTokenMalformed
	}
	var (
		claims jwt.MapClaims
		err    error
	)
	if ctx != nil {
		claims, err = v.validateMapClaims(ctx, rawIDToken, nonce, v.idTokenAudience())
	} else {
		claims, err = v.validateMapClaims(context.Background(), rawIDToken, nonce, v.idTokenAudience())
	}
	if err != nil {
		return nil, err
	}
	if iat, err := claims.GetIssuedAt(); err != nil || iat == nil {
		return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "iat claim is required"})
	}
	if err := v.validateIDTokenBindings(rawIDToken, rawAccessToken, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *TokenValidator) ValidateAccessToken(ctx context.Context, rawAccessToken string) (jwt.MapClaims, error) {
	if v == nil {
		return nil, auth.ErrTokenMalformed
	}
	audience := v.provider.AccessTokenAudience
	if len(audience) == 0 {
		audience = v.provider.Audience
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return v.validateMapClaims(ctx, rawAccessToken, "", audience)
}

//nolint:gocyclo // Token binding checks stay explicit to keep every malformed input fail closed.
func (v *TokenValidator) validateIDTokenBindings(rawIDToken, rawAccessToken string, claims jwt.MapClaims) error {
	expectedAudience := v.idTokenAudience()
	audiences, err := claims.GetAudience()
	if err != nil {
		return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "invalid audience"})
	}
	expected := make(map[string]struct{}, len(expectedAudience))
	for _, audience := range expectedAudience {
		expected[audience] = struct{}{}
	}
	for _, audience := range audiences {
		if _, ok := expected[audience]; !ok {
			return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "untrusted audience"})
		}
	}
	rawAuthorizedParty, hasAZP := claims["azp"]
	authorizedParty, validAZP := rawAuthorizedParty.(string)
	if hasAZP {
		if !validAZP || strings.TrimSpace(authorizedParty) == "" || authorizedParty != strings.TrimSpace(v.provider.ClientID) {
			return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "invalid authorized party"})
		}
	}
	if len(audiences) > 1 && !hasAZP {
		return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "authorized party is required for multiple audiences"})
	}
	rawHash, hasHash := claims["at_hash"]
	if !hasHash {
		return nil
	}
	hashValue, validHash := rawHash.(string)
	if !validHash || strings.TrimSpace(hashValue) == "" {
		return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "invalid at_hash"})
	}
	if strings.TrimSpace(rawAccessToken) == "" {
		return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "access token is required for at_hash"})
	}
	algorithm, err := tokenAlgorithm(rawIDToken)
	if err != nil {
		return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "invalid token header"})
	}
	expectedHash, err := accessTokenHash(algorithm, rawAccessToken)
	if err != nil || subtle.ConstantTimeCompare([]byte(hashValue), []byte(expectedHash)) != 1 {
		return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "invalid at_hash"})
	}
	return nil
}

func tokenAlgorithm(raw string) (string, error) {
	token, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil || token == nil || token.Method == nil {
		return "", fmt.Errorf("invalid token")
	}
	return token.Method.Alg(), nil
}

func accessTokenHash(algorithm, token string) (string, error) {
	var digest []byte
	switch {
	case strings.HasSuffix(algorithm, "256"):
		sum := sha256.Sum256([]byte(token))
		digest = sum[:]
	case strings.HasSuffix(algorithm, "384"):
		sum := sha512.Sum384([]byte(token))
		digest = sum[:]
	case strings.HasSuffix(algorithm, "512"):
		sum := sha512.Sum512([]byte(token))
		digest = sum[:]
	default:
		return "", fmt.Errorf("unsupported hash algorithm")
	}
	return base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2]), nil
}

func (v *TokenValidator) validateMapClaims(ctx context.Context, tokenString string, nonce string, audience []string) (jwt.MapClaims, error) {
	if v == nil {
		return nil, auth.ErrTokenMalformed
	}
	if strings.Count(tokenString, ".") != 2 {
		return nil, auth.ErrTokenMalformed
	}
	if err := validateEncodedTokenSize(tokenString, v.provider.Limits.normalized().EncodedTokenBytes); err != nil {
		return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "encoded token exceeds limit"})
	}

	claims := jwt.MapClaims{}
	parserOptions := []jwt.ParserOption{
		jwt.WithIssuer(v.metadata.Issuer),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(v.clock),
	}
	if len(audience) > 0 {
		parserOptions = append(parserOptions, jwt.WithAudience(audience...))
	}
	parser := jwt.NewParser(parserOptions...)

	token, err := parser.ParseWithClaims(tokenString, claims, v.keyfunc(ctx))
	if err != nil {
		return nil, v.normalizeValidationError(err)
	}
	if token == nil || !token.Valid {
		return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "invalid token"})
	}

	if nonce != "" {
		tokenNonce, _ := claims["nonce"].(string)
		if tokenNonce != nonce {
			return nil, cloneWithProvider(ErrInvalidNonce, v.provider.Key, nil)
		}
	}
	if _, ok := claims["iat"]; !ok {
		return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "issued-at is required"})
	}
	if issuedAt, err := claims.GetIssuedAt(); err != nil || issuedAt == nil {
		return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "issued-at is required"})
	}

	return claims, nil
}

func (v *TokenValidator) idTokenAudience() []string {
	if v == nil {
		return nil
	}
	if len(v.provider.IDTokenAudience) > 0 {
		return append([]string(nil), v.provider.IDTokenAudience...)
	}
	clientID := strings.TrimSpace(v.provider.ClientID)
	if clientID == "" {
		return nil
	}
	return []string{clientID}
}

//nolint:gocyclo // Algorithm and key-type rejection branches are intentionally explicit.
func (v *TokenValidator) keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		alg := ""
		if token != nil && token.Method != nil {
			alg = token.Method.Alg()
		}
		if alg == "" || alg == "none" {
			return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "unexpected signing algorithm", "alg": alg})
		}
		if _, ok := v.algSet[alg]; !ok {
			return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "unexpected signing algorithm", "alg": alg})
		}

		kid, _ := token.Header["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "missing kid"})
		}

		if ctx == nil {
			ctx = context.Background()
		}
		key, ok, err := v.jwks.key(ctx, kid)
		if err != nil {
			return nil, cloneWithProvider(ErrDiscoveryFailed, v.provider.Key, map[string]any{"cause": "JWKS lookup failed"})
		}
		if !ok {
			return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "unknown kid", "kid": kid})
		}
		if key.Algorithm != "" && key.Algorithm != alg {
			return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "jwk alg mismatch", "kid": kid})
		}
		if !key.allowsSigning() {
			return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "jwk is not usable for signing", "kid": kid})
		}

		switch {
		case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"):
			return key.rsaPublicKey()
		case alg == "ES256":
			return key.ecPublicKey()
		default:
			return nil, cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "unsupported signing algorithm", "alg": alg})
		}
	}
}

func (v *TokenValidator) normalizeValidationError(err error) error {
	if err == nil {
		return nil
	}
	if stderrors.Is(err, jwt.ErrTokenMalformed) {
		return auth.ErrTokenMalformed
	}
	if stderrors.Is(err, jwt.ErrTokenExpired) {
		clone := auth.ErrTokenExpired.Clone()
		if clone == nil {
			return auth.ErrTokenExpired
		}
		return clone.WithMetadata(map[string]any{"provider": v.provider.Key, "cause": "token expired"})
	}
	if stderrors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		stderrors.Is(err, jwt.ErrTokenInvalidAudience) ||
		stderrors.Is(err, jwt.ErrTokenInvalidIssuer) ||
		stderrors.Is(err, jwt.ErrTokenRequiredClaimMissing) ||
		stderrors.Is(err, jwt.ErrTokenUsedBeforeIssued) ||
		stderrors.Is(err, jwt.ErrTokenNotValidYet) {
		return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "token validation failed"})
	}
	if strings.Contains(err.Error(), TextCodeOIDCInvalidIDToken) ||
		strings.Contains(err.Error(), TextCodeOIDCDiscoveryFailed) {
		return err
	}
	return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": "token validation failed"})
}

func allowedAlgorithmSet(provider ProviderConfig, metadata DiscoveryMetadata) map[string]struct{} {
	source := provider.AllowedAlgorithms
	if len(source) == 0 {
		source = metadata.Algorithms
	}
	if len(source) == 0 {
		source = []string{"RS256"}
	}
	out := make(map[string]struct{}, len(source))
	for _, alg := range source {
		alg = strings.TrimSpace(alg)
		if alg != "" {
			out[alg] = struct{}{}
		}
	}
	return out
}

func rejectUnsupportedConfiguredAlgorithms(provider ProviderConfig, algSet map[string]struct{}) error {
	if len(provider.AllowedAlgorithms) == 0 {
		return nil
	}
	for alg := range algSet {
		if !supportedSigningAlgorithm(alg) {
			return cloneWithProvider(ErrInvalidConfig, provider.Key, map[string]any{
				"field": "allowed_algorithms",
				"alg":   alg,
				"cause": "unsupported signing algorithm",
			})
		}
	}
	return nil
}

func supportedSigningAlgorithm(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256":
		return true
	default:
		return false
	}
}

func mapTokenClaimsToAuth(claims jwt.MapClaims) *auth.JWTClaims {
	registered := jwt.RegisteredClaims{}
	if sub, _ := claims["sub"].(string); sub != "" {
		registered.Subject = sub
	}
	if iss, _ := claims["iss"].(string); iss != "" {
		registered.Issuer = iss
	}
	if aud, err := claims.GetAudience(); err == nil {
		registered.Audience = aud
	}
	if exp, err := claims.GetExpirationTime(); err == nil {
		registered.ExpiresAt = exp
	}
	if iat, err := claims.GetIssuedAt(); err == nil {
		registered.IssuedAt = iat
	}
	if nbf, err := claims.GetNotBefore(); err == nil {
		registered.NotBefore = nbf
	}
	if jti, _ := claims["jti"].(string); jti != "" {
		registered.ID = jti
	}

	role, _ := claims["role"].(string)
	if role == "" {
		role = string(auth.RoleMember)
	}

	metadata := make(map[string]any)
	for k, v := range claims {
		switch k {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "role":
			continue
		default:
			metadata[k] = v
		}
	}

	return &auth.JWTClaims{
		RegisteredClaims: registered,
		UID:              registered.Subject,
		UserRole:         role,
		Metadata:         metadata,
	}
}

type IDTokenValidator interface {
	ValidateIDToken(ctx context.Context, rawIDToken string, nonce string) (jwt.MapClaims, error)
}

var _ auth.TokenValidator = (*TokenValidator)(nil)
