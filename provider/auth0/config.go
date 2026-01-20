package auth0

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/validator"
)

// Config holds Auth0 configuration for token validation.
type Config struct {
	// Domain is the Auth0 tenant domain (e.g., "example.us.auth0.com").
	Domain string

	// Audience is the API identifier(s) to validate against.
	Audience []string

	// Issuer overrides the default issuer URL (optional).
	// Default: "https://{Domain}/".
	Issuer string

	// CacheTTL is how long to cache JWKS keys.
	// Default: 5 minutes.
	CacheTTL time.Duration

	// ClaimsMapper customizes claim mapping (optional).
	ClaimsMapper ClaimsMapper

	// CustomClaims defines custom claim types to extract.
	CustomClaims func() validator.CustomClaims

	// ContextFunc provides a context for JWKS fetch/validation.
	// Default: context.Background.
	ContextFunc func() context.Context
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(domain string, audience []string) Config {
	return Config{
		Domain:   domain,
		Audience: audience,
		CacheTTL: 5 * time.Minute,
	}
}

func (c Config) issuerURL() string {
	if c.Issuer != "" {
		return normalizeIssuer(c.Issuer)
	}

	domain := strings.TrimSpace(c.Domain)
	if domain == "" {
		return ""
	}

	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return normalizeIssuer(domain)
	}

	return fmt.Sprintf("https://%s/", strings.TrimSuffix(domain, "/"))
}

func normalizeIssuer(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return issuer
	}
	if strings.HasSuffix(issuer, "/") {
		return issuer
	}
	return issuer + "/"
}
