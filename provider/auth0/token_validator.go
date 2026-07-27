package auth0

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/social"
	josejwt "gopkg.in/square/go-jose.v2/jwt"
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
	if issuerURL.Scheme != "https" {
		ip := net.ParseIP(issuerURL.Hostname())
		loopback := issuerURL.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
		if issuerURL.Scheme != "http" || !cfg.AllowInsecureLoopback || !loopback {
			return nil, fmt.Errorf("auth0: issuer URL must use HTTPS")
		}
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	client := hardenedAuth0HTTPClient(cfg.HTTPClient, cfg.AllowInsecureLoopback)
	provider := jwks.NewCachingProvider(issuerURL, cacheTTL, jwks.WithCustomClient(client))

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

type auth0SecureTransport struct {
	base                  http.RoundTripper
	allowInsecureLoopback bool
}

func (t auth0SecureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, fmt.Errorf("auth0: invalid outbound request")
	}
	if request.URL.Scheme != "https" {
		ip := net.ParseIP(request.URL.Hostname())
		loopback := request.URL.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
		if request.URL.Scheme != "http" || !t.allowInsecureLoopback || !loopback {
			return nil, fmt.Errorf("auth0: outbound endpoint must use HTTPS")
		}
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response != nil && response.Body != nil {
		response.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.LimitReader(response.Body, social.MaxProviderResponseBytes+1),
			Closer: response.Body,
		}
	}
	return response, nil
}

func hardenedAuth0HTTPClient(client *http.Client, allowInsecureLoopback bool) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	if clone.Timeout <= 0 {
		clone.Timeout = 10 * time.Second
	}
	base := clone.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	clone.Transport = auth0SecureTransport{base: base, allowInsecureLoopback: allowInsecureLoopback}
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
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
	if stderrors.Is(err, jwt.ErrTokenExpired) || stderrors.Is(err, josejwt.ErrExpired) {
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
