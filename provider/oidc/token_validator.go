package oidc

import (
	"context"
	stderrors "errors"
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
	if strings.TrimSpace(metadata.Issuer) == "" || strings.TrimSpace(metadata.JWKSURI) == "" {
		return nil, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"field": "discovery_metadata"})
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
		provider:  provider,
		metadata:  metadata,
		jwks:      newJWKSCache(metadata.JWKSURI, provider.CacheTTL, options.httpClient),
		clock:     options.clock,
		algSet:    algSet,
		contextFn: options.contextFn,
	}

	if _, err := validator.jwks.keysSnapshot(ctx, true); err != nil {
		return nil, cloneWithProvider(ErrDiscoveryFailed, provider.Key, map[string]any{"cause": err.Error()})
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
	return claims, nil
}

func (v *TokenValidator) validateMapClaims(ctx context.Context, tokenString string, nonce string, audience []string) (jwt.MapClaims, error) {
	if v == nil {
		return nil, auth.ErrTokenMalformed
	}
	if strings.Count(tokenString, ".") != 2 {
		return nil, auth.ErrTokenMalformed
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
			return nil, cloneWithProvider(ErrDiscoveryFailed, v.provider.Key, map[string]any{"cause": err.Error()})
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
		return clone.WithMetadata(map[string]any{"provider": v.provider.Key, "cause": err.Error()})
	}
	if stderrors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		stderrors.Is(err, jwt.ErrTokenInvalidAudience) ||
		stderrors.Is(err, jwt.ErrTokenInvalidIssuer) ||
		stderrors.Is(err, jwt.ErrTokenRequiredClaimMissing) ||
		stderrors.Is(err, jwt.ErrTokenUsedBeforeIssued) ||
		stderrors.Is(err, jwt.ErrTokenNotValidYet) {
		return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": err.Error()})
	}
	if strings.Contains(err.Error(), TextCodeOIDCInvalidIDToken) ||
		strings.Contains(err.Error(), TextCodeOIDCDiscoveryFailed) {
		return err
	}
	return cloneWithProvider(ErrInvalidIDToken, v.provider.Key, map[string]any{"cause": err.Error()})
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
	return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
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
