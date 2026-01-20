package social

import (
	"context"
	"time"
)

// SocialProvider defines the interface for OAuth2 social login providers.
type SocialProvider interface {
	// Name returns the provider identifier (e.g., "github", "google").
	Name() string

	// AuthCodeURL returns the URL to redirect users for authorization.
	// The state parameter should be included for CSRF protection.
	AuthCodeURL(state string, opts ...AuthCodeOption) string

	// Exchange trades an authorization code for an access token.
	Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*Token, error)

	// UserInfo fetches the user's profile using the access token.
	UserInfo(ctx context.Context, token *Token) (*SocialProfile, error)

	// ValidateToken checks if a token is still valid (optional).
	ValidateToken(ctx context.Context, token *Token) error

	// RefreshToken refreshes an expired access token (if supported).
	RefreshToken(ctx context.Context, refreshToken string) (*Token, error)
}

// AuthCodeOption configures the authorization URL.
type AuthCodeOption func(*authCodeConfig)

// WithScopes sets additional scopes for the auth request.
func WithScopes(scopes ...string) AuthCodeOption {
	return func(c *authCodeConfig) {
		c.scopes = append(c.scopes, scopes...)
	}
}

// WithPKCE enables PKCE with the given code challenge.
func WithPKCE(codeChallenge, method string) AuthCodeOption {
	return func(c *authCodeConfig) {
		c.codeChallenge = codeChallenge
		c.codeChallengeMethod = method
	}
}

// WithPrompt sets the prompt parameter (e.g., "consent", "select_account").
func WithPrompt(prompt string) AuthCodeOption {
	return func(c *authCodeConfig) {
		c.prompt = prompt
	}
}

// ExchangeOption configures the token exchange.
type ExchangeOption func(*exchangeConfig)

// WithCodeVerifier sets the PKCE code verifier for token exchange.
func WithCodeVerifier(verifier string) ExchangeOption {
	return func(c *exchangeConfig) {
		c.codeVerifier = verifier
	}
}

type authCodeConfig struct {
	scopes              []string
	codeChallenge       string
	codeChallengeMethod string
	prompt              string
}

type exchangeConfig struct {
	codeVerifier string
}

// AuthCodeConfig represents applied auth code options in a provider-friendly form.
type AuthCodeConfig struct {
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
}

// ExchangeConfig represents applied exchange options in a provider-friendly form.
type ExchangeConfig struct {
	CodeVerifier string
}

// ApplyAuthCodeOptions applies AuthCodeOption values and returns a normalized config.
func ApplyAuthCodeOptions(scopes []string, opts ...AuthCodeOption) AuthCodeConfig {
	cfg := authCodeConfig{scopes: append([]string(nil), scopes...)}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return AuthCodeConfig{
		Scopes:              cfg.scopes,
		CodeChallenge:       cfg.codeChallenge,
		CodeChallengeMethod: cfg.codeChallengeMethod,
		Prompt:              cfg.prompt,
	}
}

// ApplyExchangeOptions applies ExchangeOption values and returns a normalized config.
func ApplyExchangeOptions(opts ...ExchangeOption) ExchangeConfig {
	cfg := exchangeConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return ExchangeConfig{
		CodeVerifier: cfg.codeVerifier,
	}
}

// Token represents an OAuth2 token response.
type Token struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	ExpiresAt    time.Time
	Scopes       []string
	Raw          map[string]any
}

// SocialProfile represents normalized user information from a social provider.
type SocialProfile struct {
	ProviderUserID string
	Provider       string
	Email          string
	EmailVerified  bool
	Name           string
	FirstName      string
	LastName       string
	Username       string
	AvatarURL      string
	ProfileURL     string
	Raw            map[string]any
}
