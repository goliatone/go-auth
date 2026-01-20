package auth0

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/url"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-auth"
)

// TokenValidator validates Auth0-issued JWTs using JWKS.
type TokenValidator struct {
	config       Config
	validator    *validator.Validator
	claimsMapper ClaimsMapper
}

// NewTokenValidator creates a new Auth0 token validator.
func NewTokenValidator(cfg Config) (*TokenValidator, error) {
	issuer := cfg.issuerURL()
	if issuer == "" {
		return nil, fmt.Errorf("auth0: issuer or domain is required")
	}

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("auth0: invalid issuer URL: %w", err)
	}
	if issuerURL.Scheme == "" || issuerURL.Host == "" {
		return nil, fmt.Errorf("auth0: invalid issuer URL: %s", issuer)
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	provider := jwks.NewCachingProvider(issuerURL, cacheTTL)

	customClaims := cfg.CustomClaims
	if customClaims == nil {
		customClaims = func() validator.CustomClaims {
			return &Auth0CustomClaims{}
		}
	}

	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		cfg.Audience,
		validator.WithCustomClaims(customClaims),
	)
	if err != nil {
		return nil, fmt.Errorf("auth0: failed to create validator: %w", err)
	}

	mapper := cfg.ClaimsMapper
	if mapper == nil {
		mapper = &Auth0ClaimsMapper{}
	}

	return &TokenValidator{
		config:       cfg,
		validator:    jwtValidator,
		claimsMapper: mapper,
	}, nil
}

// Validate implements auth.TokenValidator.
func (v *TokenValidator) Validate(tokenString string) (auth.AuthClaims, error) {
	ctx := context.Background()
	if v.config.ContextFunc != nil {
		ctx = v.config.ContextFunc()
	}

	token, err := v.validator.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, normalizeValidationError(err)
	}

	validatedClaims, ok := token.(*validator.ValidatedClaims)
	if !ok || validatedClaims == nil {
		return nil, auth.ErrTokenMalformed
	}

	return v.claimsMapper.Map(ctx, validatedClaims)
}

func normalizeValidationError(err error) error {
	if err == nil {
		return nil
	}

	clone := auth.ErrTokenMalformed.Clone()
	if stderrors.Is(err, jwt.ErrTokenExpired) {
		clone = auth.ErrTokenExpired.Clone()
	}

	if clone == nil {
		return err
	}

	clone.Source = err
	return clone.WithMetadata(map[string]any{
		"provider": "auth0",
		"cause":    err.Error(),
	})
}
